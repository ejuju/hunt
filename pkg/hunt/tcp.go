package hunt

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"syscall"
	"time"
)

type TCPAddrInfo struct {
	Addr              *net.TCPAddr
	At                time.Time
	State             TCPPortState
	ConnError         string
	Banner            []byte
	PotentialServices []Service
	ConfirmedService  Service
}

type TCPPortState string

const (
	TCPPortStateUnknown = TCPPortState("unknown") // timeouts, unreachable, etc.
	TCPPortStateClosed  = TCPPortState("closed")  // connection explicitly refused
	TCPPortStateOpen    = TCPPortState("open")    // connection successfully established
)

// Service represents a networked application running on a server.
type Service string

// Common networked services
const (
	SrvUnknown      = Service("unknown") // special service when unknown
	SrvCPanel       = Service("cpanel")
	SrvCUPS         = Service("cups")
	SrvDNS          = Service("dns")
	SrvDocker       = Service("docker")
	SrvFTP          = Service("ftp")
	SrvIMAP         = Service("imap")
	SrvKerberos     = Service("kerberos")
	SrvHTTP         = Service("http")
	SrvMySQL        = Service("mysql")
	SrvNFS          = Service("nfs")
	SrvNTP          = Service("ntp")
	SrvPOP3         = Service("pop3")
	SrvSFTP         = Service("sftp")
	SrvSSH          = Service("ssh")
	SrvSMTP         = Service("smtp")
	SrvSquid        = Service("squid")
	SrvTelnet       = Service("telnet")
	SrvNodeExporter = Service("node-exporter")
	SrvVNC          = Service("vnc")
)

// Based on: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
var CommonTCPPorts = [65536][]Service{
	21:   {SrvFTP},
	22:   {SrvSSH},
	23:   {SrvTelnet},
	25:   {SrvSMTP},
	53:   {SrvDNS},
	80:   {SrvHTTP},
	88:   {SrvKerberos},
	110:  {SrvPOP3},
	115:  {SrvSFTP},
	143:  {SrvIMAP},
	443:  {SrvHTTP}, // HTTP over TLS
	465:  {SrvSMTP}, // SMTP over TLS
	631:  {SrvCUPS},
	993:  {SrvIMAP}, // IMAP over TLS
	995:  {SrvPOP3}, // POP3 over TLS
	2082: {SrvCPanel},
	2083: {SrvCPanel},
	2086: {SrvCPanel},
	2087: {SrvCPanel},
	2095: {SrvCPanel},
	2096: {SrvCPanel},
	2375: {SrvDocker},
	2376: {SrvDocker},
	2377: {SrvDocker},
	3306: {SrvMySQL},
	5009: {SrvVNC},
	8080: {SrvHTTP},
	9100: {SrvNodeExporter},
}

// ScanTCP always returns a result.
func ScanTCP(target *net.TCPAddr, connTimeout time.Duration, detectors ...Detector) *TCPAddrInfo {
	if connTimeout == 0 {
		connTimeout = time.Second
	}
	result := &TCPAddrInfo{Addr: target, At: time.Now()}
	raddr := target.String()
	conn, err := net.DialTimeout("tcp", raddr, connTimeout)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			result.State = TCPPortStateClosed
			return result // Connection was explicitly refused, stop here.
		}
		// Other errors could be: unreachable host, timeout, etc.
		result.State = TCPPortStateUnknown
		result.ConnError = err.Error()
		return result
	}
	defer conn.Close()
	result.State = TCPPortStateOpen

	// Try to grab banner
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buf)
	if err == nil {
		result.Banner = buf[:n]
	}

	// Guess potential services for target port
	for port, srvs := range CommonTCPPorts {
		if port == target.Port {
			result.PotentialServices = srvs
		}
	}

	// Try to detect service
	result.ConfirmedService = SrvUnknown
	for _, detect := range detectors {
		result.ConfirmedService = detect(conn)
		if result.ConfirmedService != SrvUnknown {
			return result // stop here if we detected the specific service running on port.
		}
	}
	return result
}

type Detector func(conn net.Conn) Service

// Sends a HTTP request to a remote server and reports whether the server successfully replied in HTTP.
func DetectHTTP(httpHost string, ua string) Detector {
	return func(conn net.Conn) Service {
		if httpHost == "" {
			panic(errors.New("HTTP host is mandatory"))
		}
		if ua == "" {
			ua = RandomUserAgent()
		}
		req, err := http.NewRequest(http.MethodGet, "/", nil)
		if err != nil {
			panic(fmt.Errorf("unexpected malformed request: %w", err))
		}
		req.Host = httpHost
		req.Header.Set("User-Agent", ua)
		rawReq, err := httputil.DumpRequest(req, false)
		if err != nil {
			panic(fmt.Errorf("unexpected request dump fail: %w", err))
		}

		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(rawReq)
		if err != nil {
			return SrvUnknown
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		res, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return SrvUnknown
		}
		defer res.Body.Close()
		return SrvHTTP
	}
}

var AllPorts = PortsBetween(1, 65535)

// Note: range includes "from" and "to".
func PortsBetween(from, to uint16) []uint16 {
	out := make([]uint16, 0, to-from)
	for i := from; i <= to; i++ {
		out = append(out, uint16(i))
	}
	return out
}

func CommonPorts() []uint16 {
	out := []uint16{}
	for port, srvs := range CommonTCPPorts {
		if srvs == nil {
			continue
		}
		out = append(out, uint16(port))
	}
	return out
}

func TCPAddresses(ipAddr net.IP, ports ...uint16) []*net.TCPAddr {
	out := make([]*net.TCPAddr, len(ports))
	for i, port := range ports {
		out[i] = &net.TCPAddr{IP: ipAddr, Port: int(port)}
	}
	return out
}
