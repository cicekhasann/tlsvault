package tlsdiag

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

type Rating string

const (
	RatingSecure   Rating = "A+ (SECURE)"
	RatingModerate Rating = "B (MODERATE)"
	RatingWeak     Rating = "F (INSECURE)"
)

type AuditReport struct {
	Host             string        `json:"host"`
	ResolvedIP       string        `json:"resolved_ip"`
	HandshakeTime    time.Duration `json:"handshake_time_ms"`
	TLSVersion       string        `json:"tls_version"`
	CipherSuite      string        `json:"cipher_suite"`
	Rating           Rating        `json:"rating"`
	ALPN             string        `json:"alpn"`
	ServerName       string        `json:"server_name"`
	CertSubject      string        `json:"cert_subject"`
	CertIssuer       string        `json:"cert_issuer"`
	CertExpiry       time.Time     `json:"cert_expiry"`
	DaysRemaining    int           `json:"days_remaining"`
	IsZeroRTTAllowed bool          `json:"zero_rtt_allowed"`
}

// EvaluateCipher classifies TLS cipher suite strength against zero-trust standards.
func EvaluateCipher(suiteID uint16, tlsVer uint16) (string, Rating) {
	name := tls.CipherSuiteName(suiteID)
	if name == "" {
		name = fmt.Sprintf("Unknown(0x%04x)", suiteID)
	}

	if tlsVer == tls.VersionTLS13 {
		switch suiteID {
		case tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256:
			return name, RatingSecure
		}
	}

	// Legacy TLS 1.2
	switch suiteID {
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return name, RatingModerate
	default:
		return name, RatingWeak
	}
}

func VersionToString(ver uint16) string {
	switch ver {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1 (Deprecated)"
	case tls.VersionTLS10:
		return "TLS 1.0 (Deprecated)"
	default:
		return fmt.Sprintf("0x%04x", ver)
	}
}

// AuditHost establishes a TLS connection to host:port and inspects the handshake negotiation.
func AuditHost(hostPort string, timeout time.Duration) (*AuditReport, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "443"
		hostPort = net.JoinHostPort(host, port)
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("tlsvault: dns lookup: %w", err)
	}
	resolvedIP := ips[0]

	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()

	cfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: false,
	}

	rawConn, err := dialer.Dial("tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("tlsvault: tcp dial: %w", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tlsvault: tls handshake: %w", err)
	}
	handshakeTime := time.Since(start)

	state := tlsConn.ConnectionState()
	suiteName, rating := EvaluateCipher(state.CipherSuite, state.Version)

	var certSubject, certIssuer string
	var certExpiry time.Time
	var daysRemaining int

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		certSubject = leaf.Subject.CommonName
		if certSubject == "" && len(leaf.DNSNames) > 0 {
			certSubject = leaf.DNSNames[0]
		}
		certIssuer = leaf.Issuer.CommonName
		certExpiry = leaf.NotAfter
		daysRemaining = int(time.Until(leaf.NotAfter).Hours() / 24)
	}

	return &AuditReport{
		Host:          hostPort,
		ResolvedIP:    resolvedIP,
		HandshakeTime: handshakeTime,
		TLSVersion:    VersionToString(state.Version),
		CipherSuite:   suiteName,
		Rating:        rating,
		ALPN:          state.NegotiatedProtocol,
		ServerName:    state.ServerName,
		CertSubject:   certSubject,
		CertIssuer:    certIssuer,
		CertExpiry:    certExpiry,
		DaysRemaining: daysRemaining,
	}, nil
}

// VerifyCertificateChain validates leaf against trusted roots.
func VerifyCertificateChain(leaf *x509.Certificate, roots *x509.CertPool, dnsName string) error {
	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: dnsName,
	}
	_, err := leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("tlsvault: cert verify failed: %w", err)
	}
	return nil
}

var ErrInsecureVersion = errors.New("tlsvault: protocol version is deprecated or insecure")
