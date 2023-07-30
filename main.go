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

	logAllStdout := hunt.LogToTTY(os.Stdout, hunt.AllLogTypes...)
	logAllFile := hunt.LogAllToFile("hunt.log")
	logAllToFileAndStdout := hunt.LogTo(logAllFile, logAllStdout)
	logAllToFileAndErrToStdout := hunt.LogTo(logAllFile, hunt.LogToTTY(os.Stdout, hunt.LogError))

	// Scan domain name
	domainInfo := &hunt.DomainInfo{Name: inputDomain}
	hunt.ScanDomain(domainInfo,
		hunt.LookupIPAddresses(logAllToFileAndStdout),
		hunt.LookupCanonicalName(logAllToFileAndStdout),
		hunt.LookupTextRecords(logAllToFileAndStdout),
		hunt.LookupMailServers(logAllToFileAndStdout),
		hunt.LookupNameServers(logAllToFileAndStdout),
		hunt.LookupWHOIS(logAllToFileAndErrToStdout, time.Second),
	)

	// Scan IP address (including TCP ports)
	if len(domainInfo.IPAddresses) == 0 {
		logAllStdout(hunt.LogWarning, "no IP address found for this domain")
	}
	ipAddrInfo := &hunt.IPAddrInfo{Addr: domainInfo.IPAddresses[0]}
	hunt.ScanIPAddress(ipAddrInfo,
		hunt.ScanIPAddrDomains(logAllStdout),
		hunt.ScanIPAddrTCPPorts(
			hunt.LogTo(logAllFile, hunt.LogToTTY(os.Stdout, hunt.LogSuccess)),
			hunt.CommonPorts(),
			time.Second,
			hunt.FindTCPBanner(),
			hunt.DetectHTTP(inputDomain, ""),
		),
	)

	// Scan website
	websiteInfo := &hunt.WebsiteInfo{Host: inputDomain}
	hunt.ScanWebsite(websiteInfo,
		hunt.ScanWebsiteRobotsTXT(logAllToFileAndErrToStdout, ""),
		hunt.ScanWebsitePages(
			hunt.LogTo(logAllFile, hunt.LogToTTY(os.Stdout, hunt.LogSuccess, hunt.LogError)),
			"",
			[]string{"/"},
		),
	)
}
