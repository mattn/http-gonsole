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
	useSSL          = flag.Bool("ssl", false, "use SSL")
	rememberCookies = flag.Bool("cookies", false, "remember cookies")
)

func bool2string(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
	tcp     net.Conn
	conn    *http.ClientConn
	headers map[string]string
	cookies map[string]*Cookie
	path    *vector.StringVector
}

func (s Session) Request(method, url, data string) {
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
	if err != nil {
		fmt.Fprintln(os.Stderr, "http-gonsole:", err)
		os.Exit(1)
	}
	r, err := s.conn.Read()
	if perr, ok := err.(*http.ProtocolError); ok && perr == http.ErrPersistEOF {
		// TODO: server doesn't support persistent connection, need to redial
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "http-gonsole:", err)
		os.Exit(1)
	}
	if r.StatusCode >= 500 {
		fmt.Println("\x1b[31m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m")
	} else if r.StatusCode >= 400 {
		fmt.Println("\x1b[33m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m")
	} else if r.StatusCode >= 300 {
		fmt.Println("\x1b[36m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m")
	} else if r.StatusCode >= 200 {
		fmt.Println("\x1b[32m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m")
	}
	if len(r.Header) > 0 {
		for key, val := range r.Header {
			fmt.Println("\x1b[1m" + key + "\x1b[22m: " + val)
		}
		fmt.Println()
	}
	if *rememberCookies {
		h := r.GetHeader("Set-Cookie")
		if len(h) > 0 {
			re, _ := regexp.Compile("^[^=]+=[^;]+(; *(expires=[^;]+|path=[^;,]+|domain=[^;,]+|secure))*,?")
			for {
				sep := re.AllMatchesString(h, 1)
				if len(sep) == 0 {
					break
				}
				matches := strings.Split(sep[0], ";", 999)
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
				h = h[len(sep[0]):]
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
		s.conn = http.NewClientConn(s.tcp, nil)
	} else {
		// TODO: streaming?
	}
}

// Parse a single command and execute it. (REPL without the loop part)
// Return true when the quit command is given.
func (s Session) REPL() bool {
	prompt := "\x1b[90m" + s.scheme + "://" + s.host + "/" + strings.Join(s.path.Data(), "/") + "> \x1b[39m"
	line := readline.ReadLine(&prompt)
	if len(*line) == 0 {
		return false
	}
	readline.AddHistory(*line)
	if match, _ := regexp.MatchString("^/[^ ]*$", *line); match {
		if *line == "//" {
			s.path.Resize(0, 0)
		} else {
			tmp := new(vector.StringVector)
			pp := s.path.Data()
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
			pp = tmp.Data()
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
		matches := re.MatchStrings(*line)
		s.headers[matches[1]] = matches[2]
		tmp := make(map[string]string)
		for key, val := range s.headers {
			if len(val) > 0 {
				tmp[key] = val
			}
			s.headers = tmp
		}
		return false
	}
	if match, _ := regexp.MatchString("^(GET|POST|PUT|HEAD|DELETE)(.*)$", *line); match {
		re, _ := regexp.Compile("^(GET|POST|PUT|HEAD|DELETE)(.*)$")
		matches := re.MatchStrings(*line)
		if len(matches) > 0 {
			method := matches[1]
			tmp := strings.TrimSpace(matches[2])
			if len(tmp) == 0 {
				tmp = "/" + strings.Join(s.path.Data(), "/")
			}
			data := ""
			if method == "POST" || method == "PUT" {
				data = *readline.ReadLine(nil)
			}
			s.Request(method, s.scheme+"://"+s.host+tmp, data)
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
		fmt.Println("useSSL=" + bool2string(*useSSL) + ", rememberCookies=" + bool2string(*rememberCookies))
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
	os.Stderr.WriteString("\x1b[33m\x1b[1munknown command '" + *line + "'\x1b[39m\x1b[22m\n")
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
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
		host = targetURL.Host
		if len(host) == 0 {
			fmt.Fprintln(os.Stderr, "invalid host name")
			os.Exit(-1)
		}
		if targetURL.Scheme == "https" {
			*useSSL = true
			host += ":443"
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

	var conn *http.ClientConn
	if *useSSL {
		cf := &tls.Config{Rand: rand.Reader, Time: time.Nanoseconds}
		ssl := tls.Client(tcp, cf)
		conn = http.NewClientConn(ssl, nil)
		if len(proxy) > 0 {
			tcp.Write([]byte("CONNECT " + host + " HTTP/1.0\r\n\r\n"))
			b := make([]byte, 1024)
			tcp.Read(b)
		}
		defer ssl.Close()
	} else {
		conn = http.NewClientConn(tcp, nil)
	}
	defer conn.Close()
	defer tcp.Close()

	session := &Session{
		scheme:  scheme,
		host:    host,
		tcp:     tcp,
		conn:    conn,
		headers: make(map[string]string),
		cookies: make(map[string]*Cookie),
		path:    path,
	}
	session.headers["Host"] = host

	done := false
	for !done {
		done = session.REPL()
	}
}
