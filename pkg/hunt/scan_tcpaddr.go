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

const MinPortNumber = 1
const MaxPortNumber = 1 << 16

type TCPAddrInfo struct {
	Addr             *net.TCPAddr
	State            TCPPortState
	Banner           []byte
	ConfirmedService Service
}

func (info *TCPAddrInfo) String() string {
	out := fmt.Sprintf("%s (%q)", info.Addr, info.State)
	if len(info.Banner) > 0 {
		out += fmt.Sprintf(" [%q]", info.Banner)
	}
	if info.ConfirmedService != SrvUnknown {
		out += fmt.Sprintf(" %s", info.ConfirmedService)
	}
	return out
}

type TCPAddrScanner func(info *TCPAddrInfo, conn net.Conn)

// The error is returned from net.Dial (but not on ECONNREFUSED cause this means the port is refused)
// the returned error can be a timeout or host unreachable error.
func CollectTCPAddrInfo(info *TCPAddrInfo, connTimeout time.Duration, finders ...TCPAddrScanner) error {
	if connTimeout <= 0 {
		connTimeout = time.Second
	}
	conn, err := net.DialTimeout("tcp", info.Addr.String(), connTimeout)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			info.State = TCPPortStateClosed
			return nil // Connection was explicitly refused, stop here. not an error.
		}
		// Other errors could be: unreachable host, timeout, etc.
		return err
	}
	defer conn.Close()
	info.State = TCPPortStateOpen

	// Run finders
	for _, finder := range finders {
		finder(info, conn)
	}

	return nil
}

// Sends a HTTP request to a remote server and reports whether the server successfully replied in HTTP.
func DetectHTTP(httpHost string, ua string) TCPAddrScanner {
	return func(info *TCPAddrInfo, conn net.Conn) {
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
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		res, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return
		}
		defer res.Body.Close()
		info.ConfirmedService = SrvHTTP
	}
}

func FindTCPBanner() TCPAddrScanner {
	return func(info *TCPAddrInfo, conn net.Conn) {
		// Try to grab banner
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err == nil {
			info.Banner = buf[:n]
		}
	}
}

// Note: range includes "from" and "to".
func PortsBetween(from, to int) []int {
	out := make([]int, 0, to-from)
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func AllPorts() []int { return PortsBetween(MinPortNumber, MaxPortNumber) }

func CommonPorts() []int {
	out := []int{}
	for port, srvs := range CommonTCPPorts {
		if srvs == nil {
			continue
		}
		out = append(out, port)
	}
	return out
}

func TCPAddresses(ipAddr net.IP, ports []int) []*net.TCPAddr {
	out := make([]*net.TCPAddr, len(ports))
	for i, port := range ports {
		if port < MinPortNumber || port > MaxPortNumber {
			continue
		}
		out[i] = &net.TCPAddr{IP: ipAddr, Port: port}
	}
	return out
}

type TCPPortState string

const (
	TCPPortStateUnknown = TCPPortState("")       // timeout, unreachable, etc.
	TCPPortStateClosed  = TCPPortState("closed") // connection explicitly refused
	TCPPortStateOpen    = TCPPortState("open")   // connection successfully established
)

func (s TCPPortState) String() string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}

// Service represents a networked application running on a server.
type Service string

// Common networked services
const (
	SrvUnknown      = Service("") // special service when unknown
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
	SrvSyslog       = Service("syslog")
	SrvTelnet       = Service("telnet")
	SrvNodeExporter = Service("node-exporter")
	SrvVNC          = Service("vnc")
)

// Based on: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
var CommonTCPPorts = [MaxPortNumber][]Service{
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
	514:  {SrvSyslog},
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
	9100: {SrvNodeExporter},

	// Common ports chosen by developers
	8080: {SrvHTTP},
	8081: {SrvHTTP},
	4200: {SrvHTTP},
	1111: {SrvHTTP},
	2222: {SrvHTTP},
	3333: {SrvHTTP},
	4444: {SrvHTTP},
	5555: {SrvHTTP},
	6666: {SrvHTTP},
	7777: {SrvHTTP},
	8888: {SrvHTTP},
	9999: {SrvHTTP},
}
