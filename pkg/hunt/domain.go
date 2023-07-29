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
	At            time.Time
	IPAddresses   []net.IP
	WHOIS         []byte
	NameServers   []*net.NS
	MailServers   []*net.MX
	TextRecords   []string
	CanonicalName string
	LinkedDomains []string // other domains on same IP addresses
}

func CollectDomainInfo(name string, di *DomainInfo, finders ...DomainInfoFinder) []error {
	var errs []error
	for _, finder := range finders {
		err := finder(name, di)
		if err != nil {
			errs = append(errs, err)
			continue
		}
	}
	return errs
}

// Mutates the domain info based on name.
type DomainInfoFinder func(name string, di *DomainInfo) error

func FindDomainIPAddresses() DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		recs, err := net.LookupIP(name)
		if err != nil {
			return fmt.Errorf("lookup A and AAAA records: %w", err)
		}
		di.IPAddresses = recs
		return nil
	}
}

func FindDomainWHOIS(timeout time.Duration) DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		if timeout == 0 {
			timeout = 20 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res, err := exec.CommandContext(ctx, "whois", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("exec whois: %w", err)
		}
		di.WHOIS = res
		return nil
	}
}

func FindDomainNameServers() DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		recs, err := net.LookupNS(name)
		if err != nil {
			return fmt.Errorf("lookup NS records: %w", err)
		}
		di.NameServers = recs
		return nil
	}
}

func FindDomainMailServers() DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		recs, err := net.LookupMX(name)
		if err != nil {
			return fmt.Errorf("lookup MX records: %w", err)
		}
		di.MailServers = recs
		return nil
	}
}

func FindDomainTextRecords() DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		recs, err := net.LookupTXT(name)
		if err != nil {
			return fmt.Errorf("lookup TXT records: %w", err)
		}
		di.TextRecords = recs
		return nil
	}
}

func FindDomainCanonicalName() DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		rec, err := net.LookupCNAME(name)
		if err != nil {
			return err
		}
		di.CanonicalName = rec
		return nil
	}
}

func FindDomainsOnSameIPAddresses() DomainInfoFinder {
	return func(name string, di *DomainInfo) error {
		var err error
		for _, ipAddr := range di.IPAddresses {
			recs, lookupErr := net.LookupAddr(ipAddr.String())
			if lookupErr != nil {
				if err != nil {
					err = fmt.Errorf("%w, %w", err, lookupErr)
				} else {
					err = lookupErr
				}
			}
			di.LinkedDomains = append(di.LinkedDomains, recs...)
		}
		return err
	}
}
