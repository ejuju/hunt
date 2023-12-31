package hunt

import (
	"io"
	"math/rand"
	"os"
)

var SampleUserAgents = []string{
	"Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254",
	"Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
	"Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
}

func RandomUserAgent() string { return SampleUserAgents[rand.Intn(len(SampleUserAgents))] }

type LogType string

const (
	LogSuccess = LogType("SUCCESS")
	LogError   = LogType("ERROR")
	LogWarning = LogType("WARNING")
	LogDebug   = LogType("DEBUG")
)

var AllLogTypes = []LogType{LogSuccess, LogError, LogWarning, LogDebug}

type Logger func(typ LogType, msg string)

func NoLog() Logger { return func(typ LogType, s string) {} }

func LogToTTY(w io.Writer, typs ...LogType) Logger {
	return func(typ LogType, msg string) {
		for _, showType := range typs {
			if showType == typ {
				switch typ {
				default:
					io.WriteString(w, msg)
				case LogSuccess:
					io.WriteString(w, "\033[32m"+msg+"\033[0m")
				case LogError:
					io.WriteString(w, "\033[31m"+msg+"\033[0m")
				case LogWarning:
					io.WriteString(w, "\033[33m"+msg+"\033[0m")
				case LogDebug:
					io.WriteString(w, msg)
				}
			}
		}
	}
}

func LogAllToFile(fpath string) Logger {
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	return func(typ LogType, msg string) {
		prefix := ""
		switch typ {
		case LogDebug:
			prefix = "🔎"
		case LogError:
			prefix = "❌"
		case LogSuccess:
			prefix = "🟩"
		case LogWarning:
			prefix = "🟡"
		}
		prefix += " "
		f.Write([]byte(prefix + msg))
	}
}

func LogTo(loggers ...Logger) Logger {
	return func(typ LogType, msg string) {
		for _, log := range loggers {
			log(typ, msg)
		}
	}
}
