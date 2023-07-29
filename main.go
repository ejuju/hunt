package main

import (
	"log"
	"os"
	"time"

	"github.com/ejuju/hunt/pkg/hunt"
)

func init() { log.SetFlags(log.Ltime | log.Lshortfile) }

func main() {
	inputDomain := "juliensellier.com"
	notify := hunt.LogAllTo(os.Stdout)

	// Collect domain info
	domainInfo := &hunt.DomainInfo{Name: inputDomain}
	hunt.ScanDomain(domainInfo,
		hunt.LookupIPAddresses(notify),
		hunt.LookupCanonicalName(notify),
		hunt.LookupTextRecords(notify),
		hunt.LookupMailServers(notify),
		hunt.LookupNameServers(notify),
		hunt.LookupWHOIS(hunt.NoLog(), time.Second),
	)

	// Collect IP address info
	if len(domainInfo.IPAddresses) == 0 {
		notify(hunt.LogWarning, "no IP address found for this domain")
	}
	ipAddrInfo := &hunt.IPAddrInfo{Addr: domainInfo.IPAddresses[0]}
	hunt.ScanIPAddress(ipAddrInfo,
		hunt.ScanIPAddrDomains(notify),
		hunt.ScanIPAddrTCPPorts(notify, hunt.CommonPorts(), time.Second),
	)
}
