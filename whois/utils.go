package whois

import (
	"fmt"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"
)

func tableSummary(data [][]string, headers []string) {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)

	for _, v := range data {
		table.Append(v)
	}
	table.Render() // Send output
}

// PrintWhoisResults prints whoisresults to the console
func PrintWhoisResults(results *WhoisResults) {
	println("Expiring")
	println("========")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"registrarDomainName", "domain", "days"})
	for _, v := range results.Expiring {
		table.Append([]string{v["registrarDomainName"].(string),
			v["domain"].(string),
			fmt.Sprintf("%v", v["days"].(int))})
	}
	table.Render() // Send output

	println("Domains")
	println("========")
	table2 := tablewriter.NewWriter(os.Stdout)
	table2.SetHeader([]string{"registrarDomainName", "registrarExpirationDate", "domain", "days"})
	for _, v := range results.Domains {
		table2.Append([]string{
			v["registrarDomainName"].(string),
			fmt.Sprintf("%v", v["registrarExpirationDate"].(time.Time)),
			v["domain"].(string),
			fmt.Sprintf("%v", v["days"]),
		})
	}
	table2.Render() // Send output
}
