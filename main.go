package main

import (
	"log"
	"os"
	"time"

	"github.com/ejuju/hunt/pkg/hunt"
)

func init() { log.SetFlags(log.Ltime | log.Lshortfile) }

func main() {
	inputDomain := os.Args[1]
	log := hunt.LogToTTY(os.Stdout, hunt.AllLogTypes...)

	// Scan domain name
	domainInfo := &hunt.DomainInfo{Name: inputDomain}
	hunt.ScanDomain(domainInfo,
		hunt.LookupIPAddresses(log),
		hunt.LookupCanonicalName(log),
		hunt.LookupTextRecords(log),
		hunt.LookupMailServers(log),
		hunt.LookupNameServers(log),
		hunt.LookupWHOIS(hunt.LogToTTY(os.Stdout, hunt.LogError), time.Second),
	)

	// Scan IP address (including TCP ports)
	if len(domainInfo.IPAddresses) == 0 {
		log(hunt.LogWarning, "no IP address found for this domain")
	}
	ipAddrInfo := &hunt.IPAddrInfo{Addr: domainInfo.IPAddresses[0]}
	hunt.ScanIPAddress(ipAddrInfo,
		hunt.ScanIPAddrDomains(log),
		hunt.ScanIPAddrTCPPorts(hunt.LogToTTY(os.Stdout, hunt.LogSuccess), hunt.CommonPorts(), time.Second),
	)

	// Scan website
	websiteInfo := &hunt.WebsiteInfo{Host: inputDomain}
	tryPaths := []string{"/", "/robots.txt"}
	hunt.ScanWebsite(websiteInfo,
		hunt.ScanWebsiteRobotsTXT(hunt.NoLog(), ""),
		hunt.ScanWebsitePages(hunt.LogToTTY(os.Stdout, hunt.LogSuccess, hunt.LogError), "", tryPaths),
	)
}
