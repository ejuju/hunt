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

func ScanIPAddrDomains(log Logger) IPAddrScanner {
	return func(info *IPAddrInfo) {
		recs, err := net.LookupAddr(info.Addr.String())
		if err != nil {
			log(LogError, fmt.Sprintf("%q: lookup address: %s\n", info.Addr, err))
			return
		}
		info.Domains = recs
		for _, rec := range recs {
			log(LogSuccess, fmt.Sprintf("%q has domain: %s\n", info.Addr, rec))
		}
	}
}

func ScanIPAddrTCPPorts(log Logger, ports []int, connTimeout time.Duration, finders ...TCPAddrScanner) IPAddrScanner {
	return func(info *IPAddrInfo) {
		for _, port := range ports {
			tcpAddrInfo := &TCPAddrInfo{Addr: &net.TCPAddr{IP: info.Addr, Port: port}}
			info.TCP[port] = tcpAddrInfo
			err := CollectTCPAddrInfo(tcpAddrInfo, connTimeout, finders...)
			if err != nil {
				log(LogWarning, fmt.Sprintf("%s: scan TCP: %s\n", tcpAddrInfo.Addr, err))
				continue
			}
			if tcpAddrInfo.State == TCPPortStateOpen {
				log(LogSuccess, fmt.Sprintf("%s\n", tcpAddrInfo))
			} else {
				log(LogDebug, fmt.Sprintf("%s\n", tcpAddrInfo))
			}
		}
	}
}
