package tlsdiag

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cicekhasann/tlsvault/pkg/record"
)

func TestEvaluateCipher(t *testing.T) {
	// TLS 1.3 ChaCha20 -> A+
	name, rating := EvaluateCipher(tls.TLS_CHACHA20_POLY1305_SHA256, tls.VersionTLS13)
	if rating != RatingSecure {
		t.Fatalf("expected RatingSecure for %s, got %s", name, rating)
	}

	// TLS 1.3 AES-GCM -> A+
	_, rating = EvaluateCipher(tls.TLS_AES_256_GCM_SHA384, tls.VersionTLS13)
	if rating != RatingSecure {
		t.Fatalf("expected RatingSecure for AES_256_GCM, got %s", rating)
	}

	// Legacy TLS 1.2 -> Moderate or Weak
	_, rating = EvaluateCipher(tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS12)
	if rating != RatingWeak {
		t.Fatalf("expected RatingWeak for CBC suite, got %s", rating)
	}
}

func TestRecordHeaderParse(t *testing.T) {
	// 5-byte header: Handshake (22), TLS 1.2 (0x0303), length 512 (0x0200)
	raw := []byte{0x16, 0x03, 0x03, 0x02, 0x00}
	hdr, err := record.ParseHeader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}

	if hdr.Type != record.TypeHandshake {
		t.Fatalf("expected Handshake, got %s", hdr.Type)
	}
	if hdr.Length != 512 {
		t.Fatalf("expected length 512, got %d", hdr.Length)
	}
}

func TestLocalTLSHandshakeAudit(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, cfg)
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	// Connect client
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer rawClient.Close()

	tlsClient := tls.Client(rawClient, clientCfg)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("tls handshake failed: %v", err)
	}

	st := tlsClient.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 negotiation, got %s", VersionToString(st.Version))
	}
	if st.NegotiatedProtocol != "h2" {
		t.Fatalf("expected h2 ALPN negotiation, got %s", st.NegotiatedProtocol)
	}
}

func BenchmarkEvaluateCipher(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateCipher(tls.TLS_AES_256_GCM_SHA384, tls.VersionTLS13)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
