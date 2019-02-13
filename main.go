package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/howeyc/gopass"
	"github.com/joushou/qp"
	"github.com/joushou/qptools/fileserver"
)

var (
	address     = flag.String("address", "localhost:30000", "address to bind on")
	usingOAuth  = flag.Bool("oauth", false, "use OAuth 1.0 for authorization")
	ckey        = flag.String("ckey", "", "consumer key for OAuth")
	pkey        = flag.String("pkey", "", "private key file for OAuth")
	pass        = flag.Bool("pass", false, "use password for authorization")
	jiraURLStr  = flag.String("url", "", "jira URL")
	maxlisting  = flag.Int("maxlisting", 100, "max directory listing length")
)

func main() {
	flag.Parse()

	jiraURL, err := url.Parse(*jiraURLStr)
	if err != nil {
		fmt.Printf("Could not parse JIRA URL: %v\n", err)
		return
	}

	client := &Client{
		Client:      &http.Client{},
		usingOAuth:  *usingOAuth,
		jiraURL:     jiraURL,
		maxlisting:  *maxlisting,
	}

	switch {
	case *pass:
		var username string
		fmt.Printf("Username: ")
		_, err = fmt.Scanln(&username)
		if err == nil {
			fmt.Printf("Password: ")
			password, err := gopass.GetPasswdMasked()
			if err != nil {
				fmt.Printf("Could not read password: %v\n", err)
				return
			}

			client.user = username
			client.pass = string(password)
		} else {
			fmt.Printf("Continuing without authentication.\n")
		}
	case *usingOAuth:
		if err := client.oauth(*ckey, *pkey); err != nil {
			fmt.Printf("Could not complete oauth handshake: %v\n", err)
			return
		}
	default:
		fmt.Printf("Continuing without authentication\n")
	}

	root, err := NewJiraDir("", 0555|qp.DMDIR, "jira", "jira", client, &JiraView{})
	if err != nil {
		fmt.Printf("Could not create JIRA view\n")
		return
	}

	l, err := net.Listen("tcp", *address)
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
