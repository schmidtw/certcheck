// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
)

var cli struct {
	URL     string        `arg:"" help:"URL or host to check (e.g., https://example.com, example.com:443)"`
	Timeout time.Duration `short:"t" default:"10s" help:"Connection timeout"`
	Brief   bool          `short:"b" help:"Show brief output (subject, issuer, validity only)"`
	JSON    bool          `short:"j" help:"Output in JSON format"`
	Verify  bool          `short:"v" help:"Verify certificate chain (fail on invalid certs)"`
}

func main() {
	kong.Parse(&cli,
		kong.Name("cert-check"),
		kong.Description("Examine TLS certificate chains from remote servers"),
		kong.UsageOnError(),
	)

	host, port, err := parseURL(cli.URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing URL: %v\n", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("%s:%s", host, port)

	dialer := &net.Dialer{Timeout: cli.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: !cli.Verify,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Fprintf(os.Stderr, "No certificates received from server\n")
		os.Exit(1)
	}

	if cli.JSON {
		printJSON(addr, certs)
		return
	}

	fmt.Printf("Certificate chain for %s\n", addr)
	fmt.Println(strings.Repeat("=", 60))

	for i, cert := range certs {
		certType := getCertType(i, len(certs), cert)
		if cli.Brief {
			printCertificateBrief(i, cert, certType)
		} else {
			printCertificate(i, cert, certType)
		}
	}
}

func parseURL(rawURL string) (host, port string, err error) {
	// Add scheme if missing
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}

	host = u.Hostname()
	port = u.Port()

	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "ldaps":
			port = "636"
		case "imaps":
			port = "993"
		case "pop3s":
			port = "995"
		case "smtps":
			port = "465"
		default:
			port = "443"
		}
	}

	return host, port, nil
}

func getCertType(index, total int, cert *x509.Certificate) string {
	if index == 0 {
		return "LEAF"
	}
	if cert.IsCA {
		if index == total-1 || cert.Subject.String() == cert.Issuer.String() {
			return "ROOT"
		}
		return "INTERMEDIATE"
	}
	return "INTERMEDIATE"
}

func printCertificate(index int, cert *x509.Certificate, certType string) {
	fmt.Printf("\n[%d] %s CERTIFICATE\n", index, certType)
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("Subject:         %s\n", cert.Subject.String())
	fmt.Printf("Issuer:          %s\n", cert.Issuer.String())
	fmt.Println()

	fmt.Printf("Serial Number:   %s\n", cert.SerialNumber.String())
	fmt.Printf("Version:         %d\n", cert.Version)
	fmt.Println()

	fmt.Printf("Not Before:      %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:       %s\n", cert.NotAfter.Format(time.RFC3339))

	// Check validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		fmt.Printf("Status:          NOT YET VALID\n")
	} else if now.After(cert.NotAfter) {
		fmt.Printf("Status:          EXPIRED\n")
	} else {
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		fmt.Printf("Status:          Valid (%d days remaining)\n", daysRemaining)
	}
	fmt.Println()

	fmt.Printf("Signature Algo:  %s\n", cert.SignatureAlgorithm.String())
	fmt.Printf("Public Key Algo: %s\n", cert.PublicKeyAlgorithm.String())

	if cert.IsCA {
		fmt.Printf("Is CA:           Yes\n")
	} else {
		fmt.Printf("Is CA:           No\n")
	}

	// Print SANs for leaf certificates
	if index == 0 {
		if len(cert.DNSNames) > 0 {
			fmt.Printf("\nDNS Names (SANs):\n")
			for _, dns := range cert.DNSNames {
				fmt.Printf("  - %s\n", dns)
			}
		}
		if len(cert.IPAddresses) > 0 {
			fmt.Printf("\nIP Addresses:\n")
			for _, ip := range cert.IPAddresses {
				fmt.Printf("  - %s\n", ip.String())
			}
		}
	}

	// Print key usages
	if cert.KeyUsage != 0 {
		fmt.Printf("\nKey Usage:\n")
		printKeyUsage(cert.KeyUsage)
	}

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("\nExtended Key Usage:\n")
		for _, usage := range cert.ExtKeyUsage {
			fmt.Printf("  - %s\n", extKeyUsageString(usage))
		}
	}

	fmt.Println()
}

func printKeyUsage(usage x509.KeyUsage) {
	usages := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}

	for _, u := range usages {
		if usage&u.flag != 0 {
			fmt.Printf("  - %s\n", u.name)
		}
	}
}

func extKeyUsageString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		return "Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	default:
		return fmt.Sprintf("Unknown (%d)", usage)
	}
}

func printCertificateBrief(index int, cert *x509.Certificate, certType string) {
	now := time.Now()
	var status string
	if now.Before(cert.NotBefore) {
		status = "NOT YET VALID"
	} else if now.After(cert.NotAfter) {
		status = "EXPIRED"
	} else {
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		status = fmt.Sprintf("Valid (%d days)", daysRemaining)
	}

	fmt.Printf("[%d] %-12s %s\n", index, certType, cert.Subject.CommonName)
	fmt.Printf("    Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("    Status: %s (expires %s)\n\n", status, cert.NotAfter.Format("2006-01-02"))
}

type certInfo struct {
	Index         int       `json:"index"`
	Type          string    `json:"type"`
	Subject       string    `json:"subject"`
	SubjectCN     string    `json:"subject_cn"`
	Issuer        string    `json:"issuer"`
	IssuerCN      string    `json:"issuer_cn"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	IsExpired     bool      `json:"is_expired"`
	IsCA          bool      `json:"is_ca"`
	SignatureAlgo string    `json:"signature_algorithm"`
	PublicKeyAlgo string    `json:"public_key_algorithm"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	IPAddresses   []string  `json:"ip_addresses,omitempty"`
	KeyUsage      []string  `json:"key_usage,omitempty"`
	ExtKeyUsage   []string  `json:"ext_key_usage,omitempty"`
}

type chainOutput struct {
	Address      string     `json:"address"`
	Certificates []certInfo `json:"certificates"`
}

func printJSON(addr string, certs []*x509.Certificate) {
	output := chainOutput{
		Address:      addr,
		Certificates: make([]certInfo, len(certs)),
	}

	now := time.Now()
	for i, cert := range certs {
		certType := getCertType(i, len(certs), cert)
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)

		info := certInfo{
			Index:         i,
			Type:          certType,
			Subject:       cert.Subject.String(),
			SubjectCN:     cert.Subject.CommonName,
			Issuer:        cert.Issuer.String(),
			IssuerCN:      cert.Issuer.CommonName,
			SerialNumber:  cert.SerialNumber.String(),
			NotBefore:     cert.NotBefore,
			NotAfter:      cert.NotAfter,
			DaysRemaining: daysRemaining,
			IsExpired:     now.After(cert.NotAfter),
			IsCA:          cert.IsCA,
			SignatureAlgo: cert.SignatureAlgorithm.String(),
			PublicKeyAlgo: cert.PublicKeyAlgorithm.String(),
		}

		if len(cert.DNSNames) > 0 {
			info.DNSNames = cert.DNSNames
		}

		if len(cert.IPAddresses) > 0 {
			info.IPAddresses = make([]string, len(cert.IPAddresses))
			for j, ip := range cert.IPAddresses {
				info.IPAddresses[j] = ip.String()
			}
		}

		info.KeyUsage = getKeyUsageStrings(cert.KeyUsage)

		if len(cert.ExtKeyUsage) > 0 {
			info.ExtKeyUsage = make([]string, len(cert.ExtKeyUsage))
			for j, usage := range cert.ExtKeyUsage {
				info.ExtKeyUsage[j] = extKeyUsageString(usage)
			}
		}

		output.Certificates[i] = info
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

func getKeyUsageStrings(usage x509.KeyUsage) []string {
	var result []string
	usages := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}

	for _, u := range usages {
		if usage&u.flag != 0 {
			result = append(result, u.name)
		}
	}
	return result
}
