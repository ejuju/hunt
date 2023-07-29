package hunt

import (
	"fmt"
	"net"
	"time"
)

type IPAddrInfo struct {
	Addr    net.IP
	Domains []string // reverse lookup
	TCP     [MaxPortNumber]*TCPAddrInfo
}

type IPAddrScanner func(info *IPAddrInfo)

func ScanIPAddress(info *IPAddrInfo, scanners ...IPAddrScanner) {
	for _, finder := range scanners {
		finder(info)
	}
}

func ScanIPAddrDomains(notify Logger) IPAddrScanner {
	return func(info *IPAddrInfo) {
		recs, err := net.LookupAddr(info.Addr.String())
		if err != nil {
			notify(LogError, fmt.Sprintf("%q: lookup address: %s\n", info.Addr, err))
			return
		}
		info.Domains = recs
		for _, rec := range recs {
			notify(LogSuccess, fmt.Sprintf("%q has domain: %s\n", info.Addr, rec))
		}
	}
}

func ScanIPAddrTCPPorts(notify Logger, ports []int, connTimeout time.Duration, finders ...TCPAddrScanner) IPAddrScanner {
	return func(info *IPAddrInfo) {
		for _, port := range ports {
			tcpAddrInfo := &TCPAddrInfo{Addr: &net.TCPAddr{IP: info.Addr, Port: port}}
			info.TCP[port] = tcpAddrInfo
			err := CollectTCPAddrInfo(tcpAddrInfo, connTimeout, finders...)
			if err != nil {
				notify(LogWarning, fmt.Sprintf("%s: scan TCP: %s\n", tcpAddrInfo.Addr, err))
				continue
			}
			if tcpAddrInfo.State == TCPPortStateOpen {
				notify(LogSuccess, fmt.Sprintf("OPEN PORT: %s\n", tcpAddrInfo))
			} else {
				notify(LogWarning, fmt.Sprintf("REFUSED: %s\n", tcpAddrInfo))
			}
		}
	}
}

func (info *IPAddrInfo) PrettyString() string {
	out := info.Addr.String() + "\n"
	for _, domain := range info.Domains {
		out += "Domain: " + domain + "\n"
	}
	for port, portInfo := range info.TCP {
		if portInfo == nil || portInfo.State != TCPPortStateOpen {
			continue
		}
		out += fmt.Sprintf("Open port %d: %s\n", port, portInfo)
	}
	return out
}
