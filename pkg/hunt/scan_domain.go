package hunt

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"
)

type DomainInfo struct {
	Name          string
	IPAddresses   []net.IP
	NameServers   []*net.NS
	MailServers   []*net.MX
	TextRecords   []string
	CanonicalName string
	WHOIS         []byte
}

type DomainScanner func(info *DomainInfo)

func ScanDomain(info *DomainInfo, scanners ...DomainScanner) {
	for _, finder := range scanners {
		finder(info)
	}
}

// Can be called without finders for simple DNS lookup.
func LookupIPAddresses(notify Logger) DomainScanner {
	return func(info *DomainInfo) {
		net.DefaultResolver.PreferGo = false
		net.DefaultResolver.StrictErrors = true
		recs, err := net.LookupIP(info.Name)
		if err != nil {
			notify(LogError, fmt.Sprintf("%q: lookup A and AAAA: %s", info.Name, err))
			return
		}
		info.IPAddresses = recs
		for _, ipAddr := range recs {
			notify(LogSuccess, fmt.Sprintf("%q has IP: %s\n", info.Name, ipAddr))
		}
	}
}

func LookupWHOIS(notify Logger, timeout time.Duration) DomainScanner {
	return func(info *DomainInfo) {
		if timeout <= 0 {
			timeout = 20 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res, err := exec.CommandContext(ctx, "whois", info.Name).CombinedOutput()
		if err != nil {
			notify(LogError, fmt.Sprintf("%q: exec whois: %s", info.Name, err))
			return
		}
		info.WHOIS = res
		notify(LogSuccess, "---\nWHOIS:\n"+string(res)+"\n---\n")
	}
}

func LookupNameServers(notify Logger) DomainScanner {
	return func(info *DomainInfo) {
		recs, err := net.LookupNS(info.Name)
		if err != nil {
			notify(LogSuccess, fmt.Sprintf("%q: lookup NS: %s\n", info.Name, err))
			return
		}
		info.NameServers = recs
		for _, ns := range recs {
			notify(LogSuccess, fmt.Sprintf("%q has NS: %s\n", info.Name, ns.Host))
		}
	}
}

func LookupMailServers(notify Logger) DomainScanner {
	return func(info *DomainInfo) {
		recs, err := net.LookupMX(info.Name)
		if err != nil {
			notify(LogError, fmt.Sprintf("%q: lookup MX records: %s", info.Name, err))
			return
		}
		info.MailServers = recs
		for _, mx := range recs {
			notify(LogSuccess, fmt.Sprintf("%q has MX: %s (%d)\n", info.Name, mx.Host, mx.Pref))
		}
	}
}

func LookupTextRecords(notify Logger) DomainScanner {
	return func(info *DomainInfo) {
		recs, err := net.LookupTXT(info.Name)
		if err != nil {
			notify(LogError, fmt.Sprintf("%q: lookup TXT records: %s", info.Name, err))
			return
		}
		info.TextRecords = recs
		for _, txt := range recs {
			notify(LogSuccess, fmt.Sprintf("%q has TXT: %s\n", info.Name, txt))
		}
	}
}

func LookupCanonicalName(notify Logger) DomainScanner {
	return func(info *DomainInfo) {
		rec, err := net.LookupCNAME(info.Name)
		if err != nil {
			notify(LogError, fmt.Sprintf("%q: lookup CNAME: %s", info.Name, err))
			return
		}
		info.CanonicalName = rec
		notify(LogSuccess, fmt.Sprintf("%q has CNAME: %s\n", info.Name, rec))
	}
}
