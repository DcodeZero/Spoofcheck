package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// CheckSPF checks if a domain has an SPF record.
func CheckSPF(domain string) bool {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		fmt.Printf("Failed to lookup TXT records for domain %s: %v\n", domain, err)
		return false
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			return true
		}
	}
	return false
}

// CheckDKIM checks if a domain has a DKIM record.
func CheckDKIM(domain string) bool {
	selector := "default" // Common DKIM selector
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	txtRecords, err := net.LookupTXT(dkimDomain)
	if err != nil {
		fmt.Printf("Failed to lookup DKIM TXT records for domain %s: %v\n", dkimDomain, err)
		return false
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DKIM1") {
			return true
		}
	}
	return false
}

// CheckDMARC checks if a domain has a DMARC record.
func CheckDMARC(domain string) bool {
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		fmt.Printf("Failed to lookup DMARC TXT records for domain %s: %v\n", dmarcDomain, err)
		return false
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			return true
		}
	}
	return false
}

func main() {
	domain := flag.String("domain", "", "The domain name to check for spoofing")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Please provide a domain name using the -domain flag.")
		return
	}

	// Check the base domain (public suffix)
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(*domain)
	if err != nil {
		fmt.Printf("Failed to determine base domain for %s: %v\n", *domain, err)
		return
	}

	spf := CheckSPF(baseDomain)
	dkim := CheckDKIM(baseDomain)
	dmarc := CheckDMARC(baseDomain)

	fmt.Printf("SPF record found for %s: %t\n", baseDomain, spf)
	fmt.Printf("DKIM record found for %s: %t\n", baseDomain, dkim)
	fmt.Printf("DMARC record found for %s: %t\n", baseDomain, dmarc)

	if !spf || !dkim || !dmarc {
		fmt.Println("Spoofing is possible for this domain.")
	} else {
		fmt.Println("Spoofing is unlikely for this domain.")
	}
}
