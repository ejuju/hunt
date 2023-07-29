package hunt

import (
	"fmt"
	"io"
	"net/http"
)

type WebsiteInfo struct {
	Host      string // domain name (optionally including subdomain)
	RobotsTXT []byte
	Pages     []string
}

type WebsiteScanner func(info *WebsiteInfo)

func ScanWebsite(info *WebsiteInfo, finders ...WebsiteScanner) {
	for _, finder := range finders {
		finder(info)
	}
}

func ScanWebsiteRobotsTXT(log Logger, ua string) WebsiteScanner {
	if ua == "" {
		ua = RandomUserAgent()
	}
	return func(info *WebsiteInfo) {
		req, err := http.NewRequest(http.MethodGet, "http://"+info.Host+"/robots.txt", nil)
		if err != nil {
			log(LogError, fmt.Sprintf("%q: create robotsTXT request: %s", info.Host, err))
			return
		}
		req.Header.Set("User-Agent", ua)
		req.Host = info.Host
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log(LogError, fmt.Sprintf("%q: send robotsTXT request: %s", info.Host, err))
			return
		}
		defer res.Body.Close()
		robotsTXT, err := io.ReadAll(res.Body)
		if err != nil {
			log(LogError, fmt.Sprintf("%q: read robotsTXT response: %s", info.Host, err))
			return
		}
		log(LogSuccess, string(robotsTXT))
		info.RobotsTXT = robotsTXT
	}
}

func ScanWebsitePages(log Logger, ua string, paths []string) WebsiteScanner {
	if ua == "" {
		ua = RandomUserAgent()
	}
	return func(info *WebsiteInfo) {
		for _, path := range paths {
			log(LogDebug, fmt.Sprintf("%q: scan website page: %s", info.Host, path))
			req, err := http.NewRequest(http.MethodGet, "http://"+info.Host+path, nil)
			if err != nil {
				log(LogError, fmt.Sprintf("%q: create page request: %s", info.Host, err))
				return
			}
			req.Header.Set("User-Agent", ua)
			req.Host = info.Host
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				log(LogError, fmt.Sprintf("%q: send page request: %s", info.Host, err))
				return
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				continue
			}
			log(LogSuccess, fmt.Sprintf("%q: has page: %s", info.Host, path))
			info.Pages = append(info.Pages, path)
		}
	}
}