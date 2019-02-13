package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
    "io"
    "io/ioutil"
	"net/http"
	"net/url"

	"github.com/mrjones/oauth"
)

type Client struct {
	*http.Client

	user, pass              string
	jiraURL                 *url.URL
	usingOAuth bool

	maxlisting int
}

type RPCError struct {
	Status      string
	Body        []byte
	Description string
}

func (rpc *RPCError) Error() string {
	return fmt.Sprintf("RPCError: %s: status %s, %s", rpc.Description, rpc.Status, rpc.Body)
}

func (c *Client) RPC(method, path string, body, target interface{}) error {
	u, err := c.jiraURL.Parse(path)
	if err != nil {
		return err
	}

    var b io.Reader
	switch x := body.(type) {
	case nil:
	case []byte:
		b = bytes.NewReader(x)
	default:
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		b = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, u.String(), b)
	if err != nil {
		return err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Atlassian-Token", "nocheck")

	if !c.usingOAuth {
		req.SetBasicAuth(c.user, c.pass);
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		err = &RPCError{
			Description: "request failed",
			Status:      resp.Status,
			Body:        respBody,
		}
		return err
	}

	if target != nil {
		if err := json.Unmarshal(respBody, target); err != nil {
			return err
		}
	}

	return nil

}

func (c *Client) oauth(consumerKey, privateKeyFile string) error {
	pvf, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pvf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	url1, _ := c.jiraURL.Parse("/plugins/servlet/oauth/request-token")
	url2, _ := c.jiraURL.Parse("/plugins/servlet/oauth/authorize")
	url3, _ := c.jiraURL.Parse("/plugins/servlet/oauth/access-token")

	t := oauth.NewRSAConsumer(
		consumerKey,
		privateKey,
		oauth.ServiceProvider{
			RequestTokenUrl:   url1.String(),
			AuthorizeTokenUrl: url2.String(),
			AccessTokenUrl:    url3.String(),
			HttpMethod:        "POST",
		},
	)

	t.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	requestToken, url, err := t.GetRequestTokenAndUrl("oob")
	if err != nil {
		return err
	}

	fmt.Printf("OAuth token requested. Please to go the following URL:\n\t%s\n\nEnter verification code: ", url)
	var verificationCode string
	fmt.Scanln(&verificationCode)
	accessToken, err := t.AuthorizeToken(requestToken, verificationCode)
	if err != nil {
		return err
	}
	fmt.Printf("OAuth token authorized.\n")

	client, err := t.MakeHttpClient(accessToken)
	if err != nil {
		return err
	}

	c.Client = client
	return nil
}
