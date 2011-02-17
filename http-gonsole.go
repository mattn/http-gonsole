// Speak HTTP like a local -- a simple, intuitive HTTP console
// This is a port of http://github.com/cloudhead/http-console

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/kless/go-readin/readin"
	"http"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	colors          = flag.Bool("colors", true, "colorful output")
	useSSL          = flag.Bool("ssl", false, "use SSL")
	rememberCookies = flag.Bool("cookies", false, "remember cookies")
	verbose         = flag.Bool("v", false, "be verbose, print out the request in wire format before sending")
)

// Color scheme, ref: http://linuxgazette.net/issue65/padala.html
const (
	C_Prompt = "\x1b[90m"
	C_Header = "\x1b[1m"
	C_2xx    = "\x1b[1;32m"
	C_3xx    = "\x1b[1;36m"
	C_4xx    = "\x1b[1;31m"
	C_5xx    = "\x1b[1;37;41m"
	C_Reset  = "\x1b[0m"
)

func colorize(color, s string) string {
	if runtime.GOOS != "windows" && *colors {
		return color + s + C_Reset
	}
	return s
}

type myCloser struct {
	io.Reader
}

func (myCloser) Close() os.Error { return nil }

type Cookie struct {
	Items    map[string]string
	path     string
	expires  *time.Time
	domain   string
	secure   bool
	httpOnly bool
}

type Session struct {
	scheme  string
	host    string
	conn    *http.ClientConn
	headers map[string]string
	cookie *Cookie
	path    *string
}

func dial(host string) (conn *http.ClientConn) {
	var tcp net.Conn
	var err os.Error
	proxy := os.Getenv("HTTP_PROXY")
	if len(proxy) > 0 {
		proxy_url, _ := http.ParseURL(proxy)
		tcp, err = net.Dial("tcp", "", proxy_url.Host)
	} else {
		tcp, err = net.Dial("tcp", "", host)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "http-gonsole:", err)
		os.Exit(1)
	}
	if *useSSL {
		cf := &tls.Config{Rand: rand.Reader, Time: time.Nanoseconds}
		ssl := tls.Client(tcp, cf)
		conn = http.NewClientConn(ssl, nil)
		if len(proxy) > 0 {
			tcp.Write([]byte("CONNECT " + host + " HTTP/1.0\r\n\r\n"))
			b := make([]byte, 1024)
			tcp.Read(b)
		}
	} else {
		conn = http.NewClientConn(tcp, nil)
	}
	return
}

func closeConn(conn *http.ClientConn) {
	tcp, _ := conn.Close()
	if tcp != nil {
		tcp.Close()
	}
}

func (s Session) perform(method, url, data string) {
	var req http.Request
	req.URL, _ = http.ParseURL(url)
	req.Method = method
	req.Header = s.headers
	if len(s.cookie.Items) > 0 {
		for key, value := range s.cookie.Items {
			if len(req.Header["Cookie"]) > 0 {
				req.Header["Cookie"] += "; "
			}
			req.Header["Cookie"] = key + "=" + value
		}
	}
	req.ContentLength = int64(len(data))
	req.Body = myCloser{bytes.NewBufferString(data)}
	if *verbose {
		req.Write(os.Stderr)
	}
	retry := 0
request:
	req.Body = myCloser{bytes.NewBufferString(data)} // recreate anew, in case of retry
	err := s.conn.Write(&req)
	if err != nil {
		if retry < 2 {
			if err == io.ErrUnexpectedEOF {
				// the underlying connection has been closed "gracefully"
				retry++
				closeConn(s.conn)
				s.conn = dial(s.host)
				goto request
			} else if protoerr, ok := err.(*http.ProtocolError); ok && protoerr == http.ErrPersistEOF {
				// the connection has been closed in an HTTP keepalive sense
				retry++
				closeConn(s.conn)
				s.conn = dial(s.host)
				goto request
			}
		}
		fmt.Fprintln(os.Stderr, "http-gonsole: could not send request:", err)
		os.Exit(1)
	}
response:
	r, err := s.conn.Read(&req)
	if err != nil {
		if protoerr, ok := err.(*http.ProtocolError); ok && protoerr == http.ErrPersistEOF {
			// the remote requested that this be the last request serviced,
			// we proceed as the response is still valid
			defer closeConn(s.conn)
			defer func() { s.conn = dial(s.host) }()
			goto output
		}
		fmt.Fprintln(os.Stderr, "http-gonsole: could not read response:", err)
		os.Exit(1)
	}
output:
	if len(data) > 0 { fmt.Println() }
	if r.StatusCode >= 500 {
		fmt.Printf(colorize(C_5xx, "%s %s\n"), r.Proto, r.Status)
	} else if r.StatusCode >= 400 {
		fmt.Printf(colorize(C_4xx, "%s %s\n"), r.Proto, r.Status)
	} else if r.StatusCode >= 300 {
		fmt.Printf(colorize(C_3xx, "%s %s\n"), r.Proto, r.Status)
	} else if r.StatusCode >= 200 {
		fmt.Printf(colorize(C_2xx, "%s %s\n"), r.Proto, r.Status)
	}
	if len(r.Header) > 0 {
		for key, val := range r.Header {
			fmt.Printf(colorize(C_Header, "%s: "), key)
			fmt.Println(val)
		}
		fmt.Println()
	}
	if *rememberCookies {
		h := r.GetHeader("Set-Cookie")
		if len(h) > 0 {
			re, _ := regexp.Compile("^[^=]+=[^;]+(; *(expires=[^;]+|path=[^;,]+|domain=[^;,]+|secure))*,?")
			rs := re.FindAllString(h, -1)
			for _, ss := range rs {
				m := strings.Split(ss, ";", -1)
				cookie := new(Cookie)
				for _, n := range m {
					t := strings.Split(n, "=", 2)
					if len(t) == 2 {
						t[0] = strings.Trim(t[0], " ")
						t[1] = strings.Trim(t[1], " ")
						switch t[0] {
						case "domain":
							cookie.domain = t[1]
						case "path":
							cookie.path = t[1]
						case "expires":
							tm, err := time.Parse("Fri, 02-Jan-2006 15:04:05 MST", t[1])
							if err != nil {
								tm, err = time.Parse("Fri, 02-Jan-2006 15:04:05 -0700", t[1])
							}
							cookie.expires = tm
						case "secure":
							cookie.secure = true
						case "HttpOnly":
							cookie.httpOnly = true
						default:
							cookie.Items[t[0]] = t[1]
						}
					}
				}
				s.cookie = cookie
			}
		}
	}
	h := r.GetHeader("Content-Length")
	if len(h) > 0 {
		n, _ := strconv.Atoi64(h)
		b := make([]byte, n)
		io.ReadFull(r.Body, b)
		fmt.Println(string(b))
	} else if method != "HEAD" {
		b, _ := ioutil.ReadAll(r.Body)
		fmt.Println(string(b))
	} else {
		// TODO: streaming?
	}
}

// Parse a single command and execute it. (REPL without the loop)
// Return true when the quit command is given.
func (s Session) repl() bool {
	prompt := fmt.Sprintf(colorize(C_Prompt, "%s://%s%s"), s.scheme, s.host, *s.path)
	line, err := readin.Prompt(prompt, "")
	if err != nil || line == "" {
		fmt.Println()
		return true
	}
	if match, _ := regexp.MatchString("^(/[^ \t]*)|(\\.\\.)$", line); match {
		if line == "/" || line == "//" {
			*s.path = "/"
		} else {
			*s.path = strings.Replace(path.Clean(path.Join(*s.path, line)), "\\", "/", -1)
		}
		return false
	}
	re := regexp.MustCompile("^([a-zA-Z][a-zA-Z0-9\\-]+):(.*)")
	if match := re.FindStringSubmatch(line); match != nil {
		key := match[1]
		val := strings.TrimSpace(match[2])
		if len(val) > 0 {
			s.headers[key] = val
		}
		return false
	}
	re = regexp.MustCompile("^(GET|POST|PUT|HEAD|DELETE)(.*)")
	if match := re.FindStringSubmatch(line); match != nil {
		method := match[1]
		p := strings.Replace(path.Clean(path.Join(*s.path, strings.TrimSpace(match[2]))), "\\", "/", -1)
		data := ""
		if method == "POST" || method == "PUT" {
			prompt = colorize(C_Prompt, "...")
			data, _ = readin.Prompt(prompt, "")
		}
		s.perform(method, s.scheme+"://"+s.host+p, data)
		return false
	}
	if line == "\\headers" || line == "\\h" {
		for key, val := range s.headers {
			fmt.Println(key + ": " + val)
		}
		return false
	}
	if line == "\\cookies" || line == "\\c" {
		for key, val := range s.cookie.Items {
			fmt.Println(key + ": " + val)
		}
		return false
	}
	if line == "\\options" || line == "\\o" {
		fmt.Printf("useSSL=%v, rememberCookies=%v, verbose=%v\n", *useSSL, *rememberCookies, *verbose)
		return false
	}
	if line == "\\help" || line == "\\?" {
		fmt.Println("\\headers, \\h    show active request headers\n" +
			"\\options, \\o    show options\n" +
			"\\cookies, \\c    show client cookies\n" +
			"\\help, \\?       display this message\n" +
			"\\exit, \\q, ^D   exit console\n")
		return false
	}
	if line == "\\q" || line == "\\exit" {
		return true
	}
	fmt.Fprintln(os.Stderr, "unknown command:", line)
	return false
}

func main() {
	scheme := "http"
	host := "localhost:80"
	headers := make(map[string]string)
	p := "/"
	flag.Parse()
	if flag.NArg() > 0 {
		tmp := flag.Arg(0)
		if match, _ := regexp.MatchString("^[^:]+(:[0-9]+)?$", tmp); match {
			tmp = "http://" + tmp
		}
		targetURL, err := http.ParseURL(tmp)
		if err != nil {
			fmt.Fprintln(os.Stderr, "malformed URL")
			os.Exit(-1)
		}
		host = targetURL.Host
		if len(host) == 0 {
			fmt.Fprintln(os.Stderr, "invalid host name")
			os.Exit(-1)
		}
		if match, _ := regexp.MatchString("^[^:]+:[0-9]+$", host); !match {
			host = host + ":80"
		}
		if *useSSL || targetURL.Scheme == "https" {
			*useSSL = true
			scheme = "https"
		}
		scheme = targetURL.Scheme
		info := targetURL.RawUserinfo
		if len(info) > 0 {
			enc := base64.URLEncoding
			encoded := make([]byte, enc.EncodedLen(len(info)))
			enc.Encode(encoded, []byte(info))
			headers["Authorization"] = "Basic " + string(encoded)
		}
		p = strings.Replace(path.Clean(targetURL.Path), "\\", "/", -1)
		if p == "." { p = "/" }
	} else if *useSSL {
		scheme = "https"
		host = "localhost:443"
	}
	headers["Host"] = host
	session := &Session{
		scheme:  scheme,
		host:    host,
		conn:    dial(host),
		headers: headers,
		cookie: new(Cookie),
		path:    &p,
	}
	defer closeConn(session.conn)
	done := false
	for !done {
		done = session.repl()
	}
}
