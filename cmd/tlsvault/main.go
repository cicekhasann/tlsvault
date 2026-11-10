package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cicekhasann/tlsvault/pkg/tlsdiag"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "Handshake timeout")
	jsonOutput := flag.Bool("json", false, "Output audit results in JSON format")
	httpAddr := flag.String("http", "", "Serve HTTP auditor interface (e.g. :8084)")
	flag.Parse()

	if *httpAddr != "" {
		startHTTPServer(*httpAddr)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf("\033[1;36m=== tlsvault // Zero-Trust TLS 1.3 Auditor ===\033[0m\n")
		fmt.Printf("Usage:\n")
		fmt.Printf("  tlsvault audit <host:port>\n")
		fmt.Printf("  tlsvault -http :8084\n\n")
		fmt.Printf("Example:\n")
		fmt.Printf("  tlsvault audit hasancicek.dev:443\n")
		return
	}

	target := args[0]
	if args[0] == "audit" && len(args) > 1 {
		target = args[1]
	}

	report, err := tlsdiag.AuditHost(target, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mError auditing %s:\033[0m %v\n", target, err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}

	fmt.Printf("\n\033[1;36m=== TLS Handshake & Cipher Suite Audit ===\033[0m\n")
	fmt.Printf("Target:           \033[1m%s\033[0m (%s)\n", report.Host, report.ResolvedIP)
	fmt.Printf("Handshake RTT:    \033[36m%v\033[0m\n", report.HandshakeTime)
	fmt.Printf("Protocol:         \033[32m%s\033[0m\n", report.TLSVersion)
	fmt.Printf("Cipher Suite:     %s\n", report.CipherSuite)
	fmt.Printf("Security Rating:  \033[1;32m%s\033[0m\n", report.Rating)
	fmt.Printf("ALPN Protocol:    \033[33m%s\033[0m\n", report.ALPN)
	fmt.Printf("Cert Subject:     %s\n", report.CertSubject)
	fmt.Printf("Cert Issuer:      %s\n", report.CertIssuer)
	fmt.Printf("Valid Until:      %s (\033[32m%d days remaining\033[0m)\n\n",
		report.CertExpiry.Format("2006-01-02"), report.DaysRemaining)
}

func startHTTPServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			host = "hasancicek.dev:443"
		}
		rep, err := tlsdiag.AuditHost(host, 4*time.Second)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:monospace;background:#030712;color:#2dd4bf;padding:2rem;">
<h1>tlsvault // Zero-Trust TLS Handshake Inspector</h1><p>API endpoint: /api/audit?host=...</p></body></html>`))
	})

	fmt.Printf("tlsvault HTTP auditor listening on http://localhost%s\n", addr)
	_ = http.ListenAndServe(addr, mux)
}
