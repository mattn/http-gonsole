package main

import (
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
)

func doHttp(conn *http.ClientConn, method string, url string, headers map[string]string, data string) (*http.Response, os.Error) {
	var r *http.Response;
	var err os.Error;
	var req http.Request;
	req.URL, _ = http.ParseURL(url);
	req.Method = method;
	req.Header = headers;
	err = conn.Write(&req);
	r, err = conn.Read();
	return r, err;
}

func main() {
	host := os.Args[1];
	path := "";
	headers := make(map[string]string);
	schema := "http://";

	var tcp net.Conn;
	if proxy := os.Getenv("HTTP_PROXY"); len(proxy) > 0 {
		proxy_url, _ := http.ParseURL(proxy);
		tcp, _ = net.Dial("tcp", "", proxy_url.Host);
	} else {
		tcp, _ = net.Dial("tcp", "", host);
	}
	conn := http.NewClientConn(tcp, nil);

	for {
		prompt := host + path + "> ";
		line := readline.ReadLine(&prompt);
		if len(*line) == 0 {
			continue;
		}
		readline.AddHistory(*line);
		if match, _ := regexp.MatchString("^/[^\\s]+$", *line); match {
			path = *line;
			continue;
		}
		if match, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9\\-]*:.*", *line); match {
			re, err := regexp.Compile("^([a-zA-Z][a-zA-Z0-9\\-]*):[:space:]*(.*)[:space]*$");
			if err != nil {
				fmt.Fprintln(os.Stderr, err.String());
				continue;
			}
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
		re, err := regexp.Compile("^(GET|POST|PUT|HEAD|DELETE)(.*)$");
		if err != nil {
			fmt.Fprintln(os.Stderr, err.String());
			continue;
		} else {
			matches := re.MatchStrings(*line);
			if len(matches) > 0 {
				method := matches[1];
				tmp := strings.TrimSpace(matches[2]);
				if len(tmp) > 0 {
					tmp = path;
				}
				data := "";
				if method == "POST" || method == "PUT" {
					data = *readline.ReadLine(nil);
				}
				r, err := doHttp(conn, method, schema + host + tmp, headers, data);
				if err == nil {
					if len(r.Header) > 0 {
						// TODO: colorful header display
						for key, val := range r.Header {
							println(key + ": " + val);
						}
						println();
					}
					h := r.GetHeader("Content-Length");
					if len(h) > 0 {
						n, _ := strconv.Atoi64(r.GetHeader("Content-Length"));
						b := make([]byte, n);
						io.ReadFull(r.Body, b);
						println(string(b));
					} else if method != "HEAD" {
						b, _ := ioutil.ReadAll(r.Body);
						println(string(b));
						conn = http.NewClientConn(tcp, nil);
					}
				} else {
					fmt.Fprintln(os.Stderr, err.String());
				}
			}
		}

		if *line == "\\headers" {
			for key, val := range headers {
				println(key + ": " + val);
			}
		}
		// TODO: .. to up to root path.
		// TODO: \options to display options
		// TODO: \cookies to display cookies
		if *line == "q" || *line == "exit" {
			os.Exit(0);
		}
	}
}
