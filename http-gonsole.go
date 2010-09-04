// Speak HTTP like a local -- a simple, intuitive HTTP console
// This is a port of http://github.com/cloudhead/http-console

package main

import (
	"bytes"
	"container/vector"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"http"
	"io"
	"io/ioutil"
	"net"
	"os"
	"readline"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	colors = flag.Bool("colors", true, "colorful output")
	useSSL          = flag.Bool("ssl", false, "use SSL")
	rememberCookies = flag.Bool("cookies", false, "remember cookies")
)

// Color scheme, ref: http://linuxgazette.net/issue65/padala.html
const (
	C_Prompt = "\x1b[90m"
	C_Header = "\x1b[1m"
	C_2xx = "\x1b[1;32m"
	C_3xx = "\x1b[1;36m"
	C_4xx = "\x1b[1;31m"
	C_5xx = "\x1b[1;37;41m"
	C_Reset = "\x1b[0m"
)

func colorize(color, s string) string {
	if *colors {
		return color + s + C_Reset
	}
	return s
}

type myCloser struct {
	io.Reader
}

func (myCloser) Close() os.Error { return nil }

type Cookie struct {
	value   string
	options map[string]string
}

type Session struct {
	scheme  string
	host    string
	conn    *http.ClientConn
	headers map[string]string
	cookies map[string]*Cookie
	path    *vector.StringVector
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

func (s Session) close() {
	tcp, _ := s.conn.Close()
	tcp.Close()
}

func (s Session) request(method, url, data string) {
	var req http.Request
	req.URL, _ = http.ParseURL(url)
	req.Method = method
	req.Header = s.headers
	if len(s.cookies) > 0 {
		for key, cookie := range s.cookies {
			if len(req.Header["Cookie"]) > 0 {
				req.Header["Cookie"] += "; "
			}
			req.Header["Cookie"] = key + "=" + cookie.value
		}
	}
	if len(data) > 0 {
		req.ContentLength = int64(len(data))
		req.Body = myCloser{bytes.NewBufferString(data)}
	}
	err := s.conn.Write(&req)
	if protoerr, ok := err.(*http.ProtocolError); ok && protoerr == http.ErrPersistEOF {
		// the connection has been closed in an HTTP keepalive sense
		s.conn = dial(s.host)
		err = s.conn.Write(&req)
	} else if err == io.ErrUnexpectedEOF {
		// the underlying connection has been closed "gracefully"
		s.conn = dial(s.host)
		err = s.conn.Write(&req)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "http-gonsole:", err)
		os.Exit(1)
	}
	r, err := s.conn.Read()
	if protoerr, ok := err.(*http.ProtocolError); ok && protoerr == http.ErrPersistEOF {
		// the remote requested that this be the last request serviced
		s.conn = dial(s.host)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "http-gonsole:", err)
		os.Exit(1)
	}
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
			for {
				sep := <- re.AllMatchesStringIter(h, 1)
				if len(sep) == 0 {
					break
				}
				matches := strings.Split(sep, ";", 999)
				key := ""
				cookie := &Cookie{"", make(map[string]string)}
				for n := range matches {
					tokens := strings.Split(strings.TrimSpace(matches[n]), "=", 2)
					if n == 0 {
						cookie.value = tokens[1]
						key = tokens[0]
					} else {
						cookie.options[strings.TrimSpace(tokens[0])] = strings.TrimSpace(tokens[1])
					}
				}
				s.cookies[key] = cookie
				h = h[len(sep):]
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
	prompt := fmt.Sprintf(colorize(C_Prompt, "%s://%s/%s> "), s.scheme, s.host, strings.Join(s.path.Copy(), "/"))
	line := readline.ReadLine(&prompt)
	if line == nil {
		return true
	}
	readline.AddHistory(*line)
	if match, _ := regexp.MatchString("^/[^ ]*$", *line); match {
		if *line == "//" {
			s.path.Resize(0, 0)
		} else {
			tmp := new(vector.StringVector)
			pp := s.path.Copy()
			for p := range pp {
				// remove empty element "/foo//bar" must be ["foo", "bar"]
				if len(pp[p]) > 0 {
					tmp.Push(pp[p])
				}
			}
			pp = strings.Split(*line, "/", -1)
			for p := range pp {
				if len(pp[p]) > 0 || p == len(pp)-1 {
					tmp.Push(pp[p])
				}
			}
			s.path.Resize(0, 0)
			pp = tmp.Copy()
			for p := range pp {
				s.path.Push(pp[p])
			}
		}
		return false
	}
	if *line == ".." {
		if s.path.Len() > 0 {
			s.path.Pop()
		}
		return false
	}
	if match, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9\\-]*:.*", *line); match {
		re, _ := regexp.Compile("^([a-zA-Z][a-zA-Z0-9\\-]*):[:space:]*(.*)[:space]*$")
		iter := re.AllMatchesStringIter(*line, 2)
		key := <- iter;
		val := <- iter;
		s.headers[key] = val;
		tmp := make(map[string]string)
		for key, val = range s.headers {
			if len(val) > 0 {
				tmp[key] = val
			}
			s.headers = tmp
		}
		return false
	}
	if match, _ := regexp.MatchString("^(GET|POST|PUT|HEAD|DELETE)(.*)$", *line); match {
		re, _ := regexp.Compile("^(GET|POST|PUT|HEAD|DELETE)(.*)$")
		iter := re.AllMatchesStringIter(*line, 2)
		if iter != nil {
			method := <- iter;
			tmp := strings.TrimSpace(<- iter)
			if len(tmp) == 0 {
				tmp = "/" + strings.Join(s.path.Copy(), "/")
			}
			data := ""
			if method == "POST" || method == "PUT" {
				data = *readline.ReadLine(nil)
			}
			s.request(method, s.scheme+"://"+s.host+tmp, data)
		}
		return false
	}
	if *line == "\\headers" {
		for key, val := range s.headers {
			fmt.Println(key + ": " + val)
		}
		return false
	}
	if *line == "\\cookies" {
		for key, val := range s.cookies {
			fmt.Println(key + ": " + val.value)
		}
		return false
	}
	if *line == "\\options" {
		fmt.Printf("useSSL=%v, rememberCookies=%v\n", *useSSL, *rememberCookies)
		return false
	}
	if *line == "\\help" {
		fmt.Println("\\headers  show active request headers.\n" +
			"\\options  show options.\n" +
			"\\cookies  show client cookies.\n" +
			"\\help     display this message.\n" +
			"\\exit     exit console.\n" +
			"\\q\n")
		return false
	}
	if *line == "\\q" || *line == "\\exit" {
		return true
	}
	fmt.Fprintln(os.Stderr, "unknown command:", *line)
	return false
}

func main() {
	scheme := "http"
	host := "localhost:80"
	path := new(vector.StringVector)
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
		if *useSSL || targetURL.Scheme == "https" {
			*useSSL = true
			scheme = "https";
		}
		scheme = targetURL.Scheme
		pp := strings.Split(targetURL.Path, "/", -1)
		for p := range pp {
			if len(pp[p]) > 0 || p == len(pp)-1 {
				path.Push(pp[p])
			}
		}
	} else if *useSSL {
		scheme = "https"
		host = "localhost:443"
	}
	session := &Session{
		scheme:  scheme,
		host:    host,
		conn:    dial(host),
		headers: map[string]string{"Host": host},
		cookies: make(map[string]*Cookie),
		path:    path,
	}
	defer session.close()
	done := false
	for !done {
		done = session.repl()
	}
}
