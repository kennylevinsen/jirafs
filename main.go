package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/howeyc/gopass"
	"github.com/joushou/qp"
	"github.com/joushou/qptools/fileserver"
)

var (
	usingOAuth = flag.Bool("oauth", false, "use OAuth 1.0 for authorization")
	ckey       = flag.String("ckey", "", "consumer key for OAuth")
	pkey       = flag.String("pkey", "", "private key file for OAuth")
	pass       = flag.Bool("pass", false, "use password for authorization")
	jiraURLStr = flag.String("url", "", "jira URL")
)

func main() {
	flag.Parse()

	jiraURL, err := url.Parse(*jiraURLStr)
	if err != nil {
		fmt.Printf("Could not parse JIRA URL: %v\n", err)
		return
	}

	client := &Client{Client: &http.Client{}, usingOAuth: *usingOAuth, jiraURL: jiraURL}

	switch {
	case *pass:
		var user string
		fmt.Printf("Username: ")
		_, err = fmt.Scanln(&user)
		if err == nil {
			fmt.Printf("Password: ")
			pass, err := gopass.GetPasswdMasked()
			if err != nil {
				fmt.Printf("Could not read password: %v", err)
				return
			}

			client.user = user
			client.pass = string(pass)
			client.login()

			go func() {
				t := time.NewTicker(5 * time.Minute)
				for range t.C {
					client.login()
				}
			}()
		} else {
			fmt.Printf("Continuing without authentication.\n")
		}
	case *usingOAuth:
		if err := client.oauth(*ckey, *pkey); err != nil {
			fmt.Printf("Could not complete oauth handshake: %v\n", err)
			return
		}
	}

	root, err := NewJiraDir("", 0555|qp.DMDIR, "jira", "jira", client, &JiraView{})
	if err != nil {
		fmt.Printf("Could not create JIRA view")
		return
	}

	l, err := net.Listen("tcp", ":30000")
	if err != nil {
		fmt.Printf("Could not listen: %v\n", err)
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v\n", err)
			return
		}

		f := fileserver.New(conn, root, nil)
		f.Verbosity = fileserver.Quiet
		go f.Serve()
	}

}
