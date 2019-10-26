package whois

import (
	"github.com/likexian/whois-go"
	whois_parser "github.com/likexian/whois-parser-go"
)

func CheckDomain(domain string) (info whois_parser.WhoisInfo, err error) {
	whois_raw, err := whois.Whois(domain)
	if err != nil {
		return
	}
	return whois_parser.Parse(whois_raw)
}
