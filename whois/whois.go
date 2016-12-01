package whois

import (
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
)

func CheckDomain(domain string) (info whois_parser.WhoisInfo, err error) {
	whois_raw, err := whois.Whois(domain)
	if err != nil {
		return
	}
	return whois_parser.Parser(whois_raw)
}
