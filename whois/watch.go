package whois

import (
	"github.com/Jeffail/gabs"
	"github.com/cstockton/go-conv"
	"github.com/jinzhu/now"
	"github.com/likexian/whois-parser-go"
	dostow "github.com/osiloke/dostow-contrib/store"
	// "github.com/y0ssar1an/q"
	"log"
	"strings"
	"time"

	"github.com/bradfitz/slice"
	"github.com/ungerik/go-dry"
	"gopkg.in/go-playground/pool.v3"
)

type WhoisRecordRequest struct {
	Domain string
	ID     string
}

type WhoisResults struct {
	Domains  []map[string]interface{}
	Expiring []map[string]interface{}
}

func init() {

	now.TimeFormats = append(now.TimeFormats, "2006-01-02T15:04:05.999999999Z07:00")
}
func getWhoisRecord(pos int, row *WhoisRecordRequest, store dostow.Dostow) pool.WorkFunc {
	return func(wu pool.WorkUnit) (interface{}, error) {
		domain := row.Domain
		id := row.ID
		log.Printf("checking domain [%s]\n", domain)
		record, err := CheckDomain(domain)
		if err != nil {
			return []interface{}{
				pos,
				map[string]interface{}{"id": id, "Domain": domain, "Err": err, "Pos": pos},
			}, nil
		}
		log.Printf("%s record retrieved\n", domain)
		key, err := store.Save("whois", map[string]interface{}{
			"domain":                  id,
			"registrarDomainName":     strings.ToLower(record.Registrar.DomainName),
			"registrarCreatedDate":    record.Registrar.CreatedDate,
			"registrarDomainstatus":   record.Registrar.DomainStatus,
			"registrarExpirationDate": record.Registrar.ExpirationDate,
			"registrarNameServers":    record.Registrar.NameServers,
			"registrarRegistrarId":    record.Registrar.RegistrarID,
			"registrarUpdatedDate":    record.Registrar.UpdatedDate,
			"registrarDomainId":       record.Registrar.DomainId,
			"registrarRegistrarName":  strings.ToLower(record.Registrar.RegistrarName),
			"registrarReferralURL":    record.Registrar.ReferralURL,
		})
		if err != nil {
			return nil, err
		}
		log.Printf("/domains/%s [%s] => /whois/%s\n", id, domain, key)
		if wu.IsCancelled() {
			// return values not used
			return nil, nil
		}

		return []interface{}{
			pos,
			map[string]interface{}{"id": id, "key": key, "Domain": domain, "Row": row, "Whois": record},
		}, nil // everything ok, send nil, error if not
	}
}
func asyncWhoisRecord(pos int, row *WhoisRecordRequest) pool.WorkFunc {
	return func(wu pool.WorkUnit) (interface{}, error) {
		domain := row.Domain
		id := row.ID
		log.Printf("checking domain [%s]\n", domain)
		record, err := CheckDomain(domain)
		if err != nil {
			return []interface{}{
				pos,
				map[string]interface{}{"id": id, "Domain": domain, "Err": err, "Pos": pos},
			}, nil
		}
		log.Printf("%s record retrieved\n", domain)
		log.Printf("/domains/%s [%s] => /whois/%s\n", id, domain, "")
		if wu.IsCancelled() {
			// return values not used
			return nil, nil
		}

		return []interface{}{
			pos,
			map[string]interface{}{"id": id, "key": domain, "Domain": domain, "Row": row, "Whois": record},
		}, nil // everything ok, send nil, error if not
	}
}

// WatchDostow monitors a list of domains from a dostow store
func WatchDostow(apiurl, apikey, name string) error {
	p := pool.NewLimited(10)
	store := dostow.NewStore(apiurl, apikey)
	r, err := store.All(100, 0, name)
	if err != nil {
		log.Println(err)
		return err
	}
	// resp := r.(dostow.DostowRows).Raw()
	// if conv.Int64(resp["total_count"]) == 0 {
	// 	log.Println("no domains found")
	// 	return nil
	// }
	// batch := p.Batch()
	// total := conv.Int64(resp["total_count"])
	// rows := resp["data"].([]interface{})

	// whois_info := make([]interface{}, total)
	json, _ := gabs.ParseJSON(r.(dostow.DostowRows).JSON())
	total, _ := conv.Int64(json.Path("total_count").Data())
	if total == 0 {
		log.Println("no domains found")
		return nil
	}
	batch := p.Batch()
	rows, _ := json.S("data").Children()

	go func() {
		for pos, row := range rows {
			batch.Queue(getWhoisRecord(pos, &WhoisRecordRequest{
				row.Path("domain").Data().(string),
				row.Path("id").Data().(string),
			}, store))
		}
		batch.QueueComplete()
	}()

	expiringSoon := []map[string]interface{}{}
	domains := []map[string]interface{}{}

	for r := range batch.Results() {
		if err := r.Error(); err != nil {
			// handle error
			// maybe call batch.Cancel()
			log.Println(err)
			continue
		}
		rr := r.Value().([]interface{})
		result := rr[1].(map[string]interface{})
		domain := result["Domain"].(string)
		if result["Err"] != nil {
			log.Printf("%s - %s\n", domain, result["Err"].(error).Error())
			continue
		}
		domainID := result["id"].(string)
		whoisID := result["key"].(string)
		record := result["Whois"].(whois_parser.WhoisInfo)

		createdAt, _ := now.Parse(record.Registrar.CreatedDate)
		updatedAt, _ := now.Parse(record.Registrar.UpdatedDate)
		expireAt, err := now.Parse(record.Registrar.ExpirationDate)
		domainData := map[string]interface{}{
			"domain":                  domainID,
			"whois":                   whoisID,
			"registrarDomainName":     strings.ToLower(domain),
			"registrarCreatedDate":    createdAt,
			"registrarDomainstatus":   record.Registrar.DomainStatus,
			"registrarExpirationDate": expireAt,
			"registrarNameServers":    record.Registrar.NameServers,
			"registrarRegistrarId":    record.Registrar.RegistrarID,
			"registrarUpdatedDate":    updatedAt,
			"registrarDomainId":       record.Registrar.DomainId,
			"registrarRegistrarName":  strings.ToLower(record.Registrar.RegistrarName),
			"registrarReferralURL":    record.Registrar.ReferralURL,
		}
		if err == nil {
			diff := expireAt.Sub(time.Now())
			days := int(diff.Hours() / 24)
			domainData["days"] = days
			domainData["hours"] = diff.Hours()
			domainData["minutes"] = diff.Minutes()
			domainData["seconds"] = diff.Seconds()
			log.Printf("%s expires at %s, %v days\n", record.Registrar.DomainName, expireAt, days)
			if days < 91 {
				expiringSoon = append(expiringSoon, domainData)
				continue
			}
		} else {
			log.Printf("%s could not be parsed - %v\n", record.Registrar.ExpirationDate, err)

		}
		domains = append(domains, domainData)
		// whois_info[conv.Int64(rr[0].(int))] = rr[1]

	}

	//save summary
	summary := map[string]interface{}{}
	if len(expiringSoon) > 0 {
		slice.Sort(expiringSoon[:], func(i, j int) bool {
			var iday, jday int
			if expiringSoon[i]["days"] == nil {
				iday = 100000000000
			} else {
				iday = expiringSoon[i]["days"].(int)
			}
			if expiringSoon[j]["days"] == nil {
				jday = 100000000000
			} else {
				jday = expiringSoon[j]["days"].(int)
			}
			return iday < jday
		})
		summary["expiringSoon"] = expiringSoon
	}
	if len(domains) > 0 {
		slice.Sort(domains[:], func(i, j int) bool {
			var iday, jday int
			if domains[i]["days"] == nil {
				iday = 100000000000
			} else {
				iday = domains[i]["days"].(int)
			}
			if domains[j]["days"] == nil {
				jday = 100000000000
			} else {
				jday = domains[j]["days"].(int)
			}
			return iday < jday
		})
		summary["domains"] = domains
	}
	key, err := store.Save("whoissummary", summary)
	if err != nil {
		log.Printf("unable to save summary - %s\n", err.Error())
	} else {
		log.Printf("saved summary to /whoissummary/%s \n", key)
	}
	// log.Println(whois_info)
	//Save lump of whois records in one row
	return nil

}

func handleBatchResults(batch pool.Batch) (*WhoisResults, error) {

	expiringSoon := []map[string]interface{}{}
	domains := []map[string]interface{}{}

	for r := range batch.Results() {
		if err := r.Error(); err != nil {
			// handle error
			// maybe call batch.Cancel()
			log.Println(err)
			continue
		}
		rr := r.Value().([]interface{})
		result := rr[1].(map[string]interface{})
		domain := result["Domain"].(string)
		if result["Err"] != nil {
			log.Printf("%s - %s\n", domain, result["Err"].(error).Error())
			continue
		}
		domainID := result["id"].(string)
		whoisID := result["key"].(string)
		record := result["Whois"].(whois_parser.WhoisInfo)

		createdAt, _ := now.Parse(record.Registrar.CreatedDate)
		updatedAt, _ := now.Parse(record.Registrar.UpdatedDate)
		expireAt, err := now.Parse(record.Registrar.ExpirationDate)
		domainData := map[string]interface{}{
			"domain":                  domainID,
			"whois":                   whoisID,
			"registrarDomainName":     strings.ToLower(domain),
			"registrarCreatedDate":    createdAt,
			"registrarDomainstatus":   record.Registrar.DomainStatus,
			"registrarExpirationDate": expireAt,
			"registrarNameServers":    record.Registrar.NameServers,
			"registrarRegistrarId":    record.Registrar.RegistrarID,
			"registrarUpdatedDate":    updatedAt,
			"registrarDomainId":       record.Registrar.DomainId,
			"registrarRegistrarName":  strings.ToLower(record.Registrar.RegistrarName),
			"registrarReferralURL":    record.Registrar.ReferralURL,
		}
		if err == nil {
			diff := expireAt.Sub(time.Now())
			days := int(diff.Hours() / 24)
			domainData["days"] = days
			domainData["hours"] = diff.Hours()
			domainData["minutes"] = diff.Minutes()
			domainData["seconds"] = diff.Seconds()
			log.Printf("%s expires at %s, %v days\n", record.Registrar.DomainName, expireAt, days)
			if days < 91 {
				expiringSoon = append(expiringSoon, domainData)
				continue
			}
		} else {
			log.Printf("%s could not be parsed - %v\n", record.Registrar.ExpirationDate, err)

		}
		domains = append(domains, domainData)
		// whois_info[conv.Int64(rr[0].(int))] = rr[1]

	}

	//save summary
	summary := WhoisResults{}
	if len(expiringSoon) > 0 {
		slice.Sort(expiringSoon[:], func(i, j int) bool {
			var iday, jday int
			if expiringSoon[i]["days"] == nil {
				iday = 100000000000
			} else {
				iday = expiringSoon[i]["days"].(int)
			}
			if expiringSoon[j]["days"] == nil {
				jday = 100000000000
			} else {
				jday = expiringSoon[j]["days"].(int)
			}
			return iday < jday
		})
		summary.Expiring = expiringSoon
	}
	if len(domains) > 0 {
		slice.Sort(domains[:], func(i, j int) bool {
			var iday, jday int
			if domains[i]["days"] == nil {
				iday = 100000000000
			} else {
				iday = domains[i]["days"].(int)
			}
			if domains[j]["days"] == nil {
				jday = 100000000000
			} else {
				jday = domains[j]["days"].(int)
			}
			return iday < jday
		})
		summary.Domains = domains
	}
	return &summary, nil
}

// ParseCSV parses csv domains
func ParseCSV(filename string) (*WhoisResults, error) {
	entries, err := dry.FileGetCSV(filename, time.Second*5)
	if err != nil {
		return nil, err
	}
	p := pool.NewLimited(10)
	batch := p.Batch()

	go func() {
		for pos, entry := range entries {
			batch.Queue(asyncWhoisRecord(pos, &WhoisRecordRequest{
				entry[0],
				entry[1],
			}))
		}
		batch.QueueComplete()
	}()
	return handleBatchResults(batch)
}
