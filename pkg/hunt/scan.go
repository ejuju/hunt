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

type TCPPortScanResult struct {
	At                time.Time
	ConnError         string
	State             TCPPortState
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

func ScanTCPPort(target *net.TCPAddr, connTimeout time.Duration, httpHost string) (*TCPPortScanResult, error) {
	if connTimeout == 0 {
		connTimeout = time.Second
	}
	result := &TCPPortScanResult{At: time.Now()}
	raddr := target.String()
	conn, err := net.DialTimeout("tcp", raddr, connTimeout)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			result.State = TCPPortStateClosed
			return result, nil // Connection was explicitly refused, stop here.
		}
		// Other errors could be: unreachable host, timeout, etc.
		result.State = TCPPortStateUnknown
		result.ConnError = err.Error()
		return result, nil
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

	// Check if remote port speaks HTTP
	if SpeaksHTTP(conn, httpHost) {
		result.ConfirmedService = SrvHTTP
	}

	return result, nil
}

// Sends a HTTP request to a remote server and reports whether the server successfully replied in HTTP.
func SpeaksHTTP(conn net.Conn, httpHost string) bool {
	if httpHost == "" {
		panic(errors.New("HTTP host is mandatory"))
	}
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		panic(fmt.Errorf("unexpected malformed request: %w", err))
	}
	req.Host = httpHost
	rawReq, err := httputil.DumpRequest(req, false)
	if err != nil {
		panic(fmt.Errorf("unexpected request dump fail: %w", err))
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(rawReq)
	if err != nil {
		return false
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return true
}
