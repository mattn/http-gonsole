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
	value string
	options map[string]string;
}

func doHttp(conn *http.ClientConn, method string, url string, headers map[string]string, cookies map[string]*Cookie, data string) (*http.Response, os.Error) {
	var err os.Error;
	var req http.Request;
	req.URL, _ = http.ParseURL(url);
	req.Method = method;
	req.Header = headers;
	if len(cookies) > 0 {
		for key, cookie := range cookies {
			req.Header[key] = cookie.value
		}
	}
	if len(data) > 0 {
		req.ContentLength = int64(len(data));
        req.Body = myCloser{ bytes.NewBufferString(data) }
	}
	err = conn.Write(&req);
	if err != nil {
		return nil, err;
	}
	return conn.Read();
}

func main() {
	host := "localhost:80";
	path := new(vector.StringVector);
	headers := make(map[string]string);
	cookies := make(map[string]*Cookie);
	scheme := "http";

	useSSL := flag.Bool("useSSL", false, "use SSL");
	rememberCookies := flag.Bool("rememberCookies", false, "remember cookies");
	flag.Parse();
	if flag.NArg() > 0 {
		tmp := flag.Arg(0);
		if match, _ := regexp.MatchString("^[^:]+(:[0-9]+)?$", tmp); match {
			tmp = "http://" + tmp;
		}
		targetURL, err := http.ParseURL(tmp);
		if err != nil {
			fmt.Fprintln(os.Stderr, err.String());
			os.Exit(-1);
		}
		host = targetURL.Host;
		if len(host) == 0 {
			fmt.Fprintln(os.Stderr, "invalid host name");
			os.Exit(-1);
		}
		if targetURL.Scheme == "https" {
			*useSSL = true;
			host += ":443";
		}
		scheme = targetURL.Scheme;
		pp := strings.Split(targetURL.Path, "/", -1);
		for p := range pp {
			if len(pp[p]) > 0 || p == len(pp)-1 {
				path.Push(pp[p]);
			}
		}
	} else {
		if *useSSL {
			scheme = "https";
			host = "localhost:443";
		}
	}

	headers["Host"] = host;

	var tcp net.Conn;
	proxy := os.Getenv("HTTP_PROXY");
	if len(proxy) > 0 {
		proxy_url, _ := http.ParseURL(proxy);
		tcp, _ = net.Dial("tcp", "", proxy_url.Host);
	} else {
		tcp, _ = net.Dial("tcp", "", host);
	}

	var conn *http.ClientConn;
	if *useSSL {
		cf := &tls.Config{ Rand: rand.Reader, Time: time.Nanoseconds };
		ssl := tls.Client(tcp, cf);
		conn = http.NewClientConn(ssl, nil);
		if len(proxy) > 0 {
			tcp.Write([]byte("CONNECT " + host + " HTTP/1.0\r\n\r\n"));
			b := make([]byte, 1024)
			tcp.Read(b);
		}
		defer ssl.Close();
	} else {
		conn = http.NewClientConn(tcp, nil);
	}
	defer conn.Close();
	defer tcp.Close();

	for {
		prompt := "\x1b[90m" + scheme + "://" + host + "/" + strings.Join(path.Data(), "/") + "> \x1b[39m";
		line := readline.ReadLine(&prompt);
		if len(*line) == 0 {
			continue;
		}
		readline.AddHistory(*line);
		if match, _ := regexp.MatchString("^/[^ ]*$", *line); match {
			if *line == "//" {
				path.Resize(0, 0);
			} else {
				tmp := new(vector.StringVector);
				pp := path.Data();
				for p := range pp {
					if len(pp[p]) > 0 {
						tmp.Push(pp[p]);
					}
				}
				pp = strings.Split(*line, "/", -1)
				for p := range pp {
					if len(pp[p]) > 0 || p == len(pp)-1 {
						tmp.Push(pp[p]);
					}
				}
				path = tmp;
			}
			continue;
		}
		if *line == ".." {
			if path.Len() > 0 {
				path.Pop();
			}
			continue;
		}
		if match, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9\\-]*:.*", *line); match {
			re, _ := regexp.Compile("^([a-zA-Z][a-zA-Z0-9\\-]*):[:space:]*(.*)[:space]*$");
			matches := re.MatchStrings(*line);
			headers[matches[1]] = matches[2];
			tmp := make(map[string]string);
			for key, val := range headers {
				if len(val) > 0 {
					tmp[key] = val;
				}
				headers = tmp;
			}
			continue;
		}
		if match, _ := regexp.MatchString("^(GET|POST|PUT|HEAD|DELETE)(.*)$", *line); match {
			re, _ := regexp.Compile("^(GET|POST|PUT|HEAD|DELETE)(.*)$");
			matches := re.MatchStrings(*line);
			if len(matches) > 0 {
				method := matches[1];
				tmp := strings.TrimSpace(matches[2]);
				if len(tmp) == 0 {
					tmp = "/" + strings.Join(path.Data(), "/");
				}
				data := "";
				if method == "POST" || method == "PUT" {
					data = *readline.ReadLine(nil);
				}
				r, err := doHttp(conn, method, scheme + "://" + host + tmp, headers, cookies, data);
				if err == nil {
					if r.StatusCode >= 500 {
						println("\x1b[31m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m");
					} else if r.StatusCode >= 400 {
						println("\x1b[33m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m");
					} else if r.StatusCode >= 300 {
						println("\x1b[36m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m");
					} else if r.StatusCode >= 200 {
						println("\x1b[32m\x1b[1m" + r.Proto + " " + r.Status + "\x1b[39m\x1b[22m");
					}
					if len(r.Header) > 0 {
						for key, val := range r.Header {
							println("\x1b[1m" + key + "\x1b[22m: " + val);
						}
						println();
					}
					if *rememberCookies {
						h := r.GetHeader("Set-Cookie");
						if len(h) > 0 {
							re, _ := regexp.Compile("^[^=]+=[^;]+(; *(expires=[^;]+|path=[^;,]+|domain=[^;,]+|secure))*,?");
							for {
								sep := re.AllMatchesString(h, 1);
								if len(sep) == 0 {
									break;
								}
								matches := strings.Split(sep[0], ";", 999);
								key := "";
								cookie := &Cookie{ "", make(map[string]string) };
								for n := range matches {
									tokens := strings.Split(strings.TrimSpace(matches[n]), "=", 2)
									if n == 0 {
										cookie.value = tokens[1];
										key = tokens[0]
									} else {
										cookie.options[strings.TrimSpace(tokens[0])] = strings.TrimSpace(tokens[1]);
									}
								}
								cookies[key] = cookie;
								h = h[len(sep[0]):]
							}
						}
					}
					h := r.GetHeader("Content-Length");
					if len(h) > 0 {
						n, _ := strconv.Atoi64(h);
						b := make([]byte, n);
						io.ReadFull(r.Body, b);
						println(string(b));
					} else if method != "HEAD" {
						b, _ := ioutil.ReadAll(r.Body);
						println(string(b));
						conn = http.NewClientConn(tcp, nil);
					} else {
						// TODO: streaming?
					}
				} else {
					os.Stderr.WriteString("\x1b[31m\x1b[1m" + err.String() + "\x1b[39m\x1b[22m\n");
				}
			}
			continue;
		}
		if *line == "\\headers" {
			for key, val := range headers {
				println(key + ": " + val);
			}
			continue;
		}
		if *line == "\\cookies" {
			for key, val := range cookies {
				println(key + ": " + val.value);
			}
			continue;
		}
		if *line == "\\options" {
			print("useSSL=" + bool2string(*useSSL) + ", rememberCookies=" + bool2string(*rememberCookies) + "\n");
			continue;
		}
		if *line == "\\help" {
			println("\\headers  show active request headers.\n" +
					"\\options  show options.\n" +
					"\\cookies  show client cookies.\n" +
					"\\help     display this message.\n" +
					"\\exit     exit console.\n" +
					"\\q\n")
			continue;
		}
		if *line == "\\q" || *line == "\\exit" {
			os.Exit(0);
		}
		os.Stderr.WriteString("\x1b[33m\x1b[1munknown command '" + *line + "'\x1b[39m\x1b[22m\n");
	}
}
