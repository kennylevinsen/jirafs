package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/andygrunwald/go-jira"
	"github.com/joushou/qp"
	"github.com/joushou/qptools/fileserver/trees"
	"github.com/mrjones/oauth"
)

type SearchResult struct {
	Issues []jira.Issue `json:"issues"`
}

func GetProjects(jc *Client) ([]jira.Project, error) {
	req, err := jc.NewRequest("GET", "/rest/api/2/project", nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var projects []jira.Project
	if _, err := jc.Do(req, &projects); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	return projects, nil
}

func GetTypesForProject(jc *Client, project string) ([]string, error) {
	req, err := jc.NewRequest("GET", "/rest/api/2/issuetype", nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var types []jira.IssueType
	if _, err := jc.Do(req, &types); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	ss := make([]string, len(types))
	for i, tp := range types {
		ss[i] = tp.Name
	}

	return ss, nil
}

func GetKeysForSearch(jc *Client, query string, max int) ([]string, error) {
	cmd := fmt.Sprintf("/rest/api/2/search?fields=key&maxResults=%d&jql=%s", max, url.QueryEscape(query))

	req, err := jc.NewRequest("GET", cmd, nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var s SearchResult
	if _, err := jc.Do(req, &s); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	ss := make([]string, len(s.Issues))
	for i, issue := range s.Issues {
		ss[i] = issue.Key
	}

	return ss, nil
}

func GetKeysForNIssues(jc *Client, project string, max int) ([]string, error) {
	cmd := fmt.Sprintf("/rest/api/2/search?fields=key&maxResults=%d&jql=project=%s", max, project)

	req, err := jc.NewRequest("GET", cmd, nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var s SearchResult
	if _, err := jc.Do(req, &s); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	ss := make([]string, len(s.Issues))
	for i, issue := range s.Issues {
		s := strings.Split(issue.Key, "-")
		if len(s) != 2 {
			continue
		}
		ss[i] = s[1]
	}

	return ss, nil
}

func GetIssue(jc *Client, key string) (*jira.Issue, error) {
	req, err := jc.NewRequest("GET", fmt.Sprintf("/rest/api/2/issue/%s", key), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var i jira.Issue
	if _, err = jc.Do(req, &i); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}
	return &i, nil
}

type CreateIssueResult struct {
	ID  string `json:"id,omitempty"`
	Key string `json:"key,omitempty"`
}

func CreateIssue(jc *Client, issue *jira.Issue) (string, error) {
	req, err := jc.NewRequest("POST", "/rest/api/2/issue", issue)
	if err != nil {
		return "", fmt.Errorf("could not query JIRA: %v", err)
	}

	var cir CreateIssueResult
	if _, err = jc.Do(req, &cir); err != nil {
		return "", fmt.Errorf("could not query JIRA: %v", err)
	}
	return cir.Key, nil
}

func DeleteIssue(jc *Client, issue string) error {
	req, err := jc.NewRequest("DELETE", fmt.Sprintf("/rest/api/2/issue/%s", issue), nil)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}
	return nil
}

func DeleteIssueLink(jc *Client, issueLinkID string) error {
	req, err := jc.NewRequest("DELETE", fmt.Sprintf("/rest/api/2/issueLink/%s", issueLinkID), nil)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}
	return nil
}

func LinkIssues(jc *Client, inwardKey, outwardKey, relation string) error {
	issueLink := &jira.IssueLink{
		Type: jira.IssueLinkType{
			Name: relation,
		},
		InwardIssue: &jira.Issue{
			Key: inwardKey,
		},
		OutwardIssue: &jira.Issue{
			Key: outwardKey,
		},
	}

	req, err := jc.NewRequest("POST", "/rest/api/2/issueLink", issueLink)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}
	return nil
}

type Transition struct {
	ID     string            `json:"id,omitempty"`
	Name   string            `json:"name,omitempty"`
	Fields *jira.IssueFields `json:"fields,omitempty"`
}

type TransitionResult struct {
	Transitions []Transition `json:"transitions,omitempty"`
}

func GetTransitionsForIssue(jc *Client, issue string) ([]Transition, error) {
	req, err := jc.NewRequest("GET", fmt.Sprintf("/rest/api/2/issue/%s/transitions", issue), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var tr TransitionResult
	if _, err = jc.Do(req, &tr); err != nil {
		return nil, fmt.Errorf("could no query JIRA: %v", err)
	}

	return tr.Transitions, nil
}

func TransitionIssue(jc *Client, issue, transition string) error {
	transition = strings.Replace(transition, "\n", "", -1)
	transitions, err := GetTransitionsForIssue(jc, issue)
	if err != nil {
		return err
	}
	var id string
	for _, t := range transitions {
		if transition == t.Name {
			id = t.ID
			break
		}
	}

	if id == "" {
		return fmt.Errorf("no such transition")
	}

	post := map[string]interface{}{
		"transition": map[string]interface{}{
			"id": id,
		},
	}

	req, err := jc.NewRequest("POST", fmt.Sprintf("/rest/api/2/issue/%s/transitions", issue), post)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	return nil
}

func SetFieldInIssue(jc *Client, issue, field, val string) error {
	switch field {
	case "type":
		field = "issuetype"
	}

	cmd := fmt.Sprintf("/rest/api/2/issue/%s", issue)
	method := "PUT"

	var value interface{}
	if val == "" {
		value = nil
	} else {
		value = val
	}

	fields := make(map[string]interface{})
	post := map[string]interface{}{
		"fields": fields,
	}

	switch field {
	case "labels":
		var labels []string
		if val != "" && val != "\n" {
			labels = strings.Split(val, "\n")
			if labels[len(labels)-1] == "" {
				labels = labels[:len(labels)-1]
			}
		}
		fields[field] = labels
	case "components":
		componentThing := []map[string]string{}
		components := strings.Split(val, "\n")
		for _, s := range components {
			if s == "" || s == "\n" {
				continue
			}
			thing := map[string]string{
				"name": s,
			}
			componentThing = append(componentThing, thing)
		}
		fields[field] = componentThing
	case "issuetype", "assignee", "reporter", "creator", "priority", "resolution":
		fields[field] = map[string]interface{}{
			"name": value,
		}
	default:
		fields[field] = value
	}
	req, err := jc.NewRequest(method, cmd, post)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	b, _ := httputil.DumpRequestOut(req, true)
	log.Printf("Set field body: \n%s\n", b)

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	return nil
}

type CommentResult struct {
	Comments []jira.Comment `json:"comments,omitempty"`
}

func GetCommentsForIssue(jc *Client, issue string) ([]string, error) {
	req, err := jc.NewRequest("GET", fmt.Sprintf("/rest/api/2/issue/%s/comment?maxResults=1000", issue), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var cr CommentResult
	if _, err := jc.Do(req, &cr); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var ss []string
	for _, c := range cr.Comments {
		ss = append(ss, c.ID)
	}

	return ss, nil
}

func GetComment(jc *Client, issue, id string) (*jira.Comment, error) {
	req, err := jc.NewRequest("GET", fmt.Sprintf("/rest/api/2/issue/%s/comment/%s", issue, id), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	var c jira.Comment
	if _, err := jc.Do(req, &c); err != nil {
		return nil, fmt.Errorf("could not query JIRA: %v", err)
	}

	return &c, nil
}

func SetComment(jc *Client, issue, id, body string) error {
	c := jira.Comment{
		Body: body,
	}

	req, err := jc.NewRequest("PUT", fmt.Sprintf("/rest/api/2/issue/%s/comment/%s", issue, id), c)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	return nil
}

func AddComment(jc *Client, issue, body string) error {
	c := jira.Comment{
		Body: body,
	}

	req, err := jc.NewRequest("POST", fmt.Sprintf("/rest/api/2/issue/%s/comment/", issue), c)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	return nil
}

func RemoveComment(jc *Client, issue, id string) error {
	req, err := jc.NewRequest("DELETE", fmt.Sprintf("/rest/api/2/issue/%s/comment/%s", issue, id), nil)
	if err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	if _, err = jc.Do(req, nil); err != nil {
		return fmt.Errorf("could not query JIRA: %v", err)
	}

	return nil
}

type CanOpenAndLister interface {
	CanOpen(string, qp.OpenMode) bool
	trees.Lister
}

func OpenList(l CanOpenAndLister, user string, mode qp.OpenMode) (trees.ReadWriteAtCloser, error) {
	if !l.CanOpen(user, mode) {
		return nil, errors.New("permission denied")
	}

	return &trees.ListHandle{
		Dir:  l,
		User: user,
	}, nil
}

func StringsToStats(strs []string, Perm qp.FileMode, user, group string) []qp.Stat {
	var stats []qp.Stat
	for _, str := range strs {
		stat := qp.Stat{
			Name: str,
			UID:  user,
			GID:  group,
			MUID: user,
			Mode: Perm,
		}
		stats = append(stats, stat)
	}

	return stats
}

func StringExistsInSets(str string, sets ...[]string) bool {
	for _, set := range sets {
		for _, s := range set {
			if str == s {
				return true
			}
		}
	}

	return false
}

type CloseSaverHandle struct {
	onClose func() error
	trees.ReadWriteAtCloser
}

func (csh *CloseSaverHandle) Close() error {
	err := csh.ReadWriteAtCloser.Close()
	if err != nil {
		return err
	}

	if csh.onClose != nil {
		return csh.onClose()
	}

	return nil
}

type CloseSaver struct {
	onClose func() error
	trees.File
}

func (cs *CloseSaver) Open(user string, mode qp.OpenMode) (trees.ReadWriteAtCloser, error) {
	hndl, err := cs.File.Open(user, mode)
	if err != nil {
		return nil, err
	}

	var closer func() error

	switch mode & 3 {
	case qp.OWRITE, qp.ORDWR:
		closer = cs.onClose
	}

	return &CloseSaverHandle{
		ReadWriteAtCloser: hndl,
		onClose:           closer,
	}, nil
}

func NewCloseSaver(file trees.File, onClose func() error) trees.File {
	return &CloseSaver{
		onClose: onClose,
		File:    file,
	}
}

type CommandFile struct {
	cmds map[string]func([]string) error
	*trees.SyntheticFile
}

func (cf *CommandFile) Close() error { return nil }
func (cf *CommandFile) ReadAt(p []byte, offset int64) (int, error) {
	return 0, errors.New("cannot read from command file")
}

func (cf *CommandFile) WriteAt(p []byte, offset int64) (int, error) {
	args := strings.Split(strings.Trim(string(p), " \n"), " ")
	cmd := args[0]
	args = args[1:]

	if f, exists := cf.cmds[cmd]; exists {
		err := f(args)
		if err != nil {
			log.Printf("Command %s failed: %v", cmd, err)
		}
		return len(p), err
	}
	return len(p), errors.New("no such command")
}

func (cf *CommandFile) Open(user string, mode qp.OpenMode) (trees.ReadWriteAtCloser, error) {
	if !cf.CanOpen(user, mode) {
		return nil, trees.ErrPermissionDenied
	}

	return cf, nil
}

func NewCommandFile(name string, perms qp.FileMode, user, group string, cmds map[string]func([]string) error) *CommandFile {
	return &CommandFile{
		cmds:          cmds,
		SyntheticFile: trees.NewSyntheticFile(name, perms, user, group),
	}
}

type JiraDir struct {
	thing  interface{}
	client *Client
	*trees.SyntheticDir
}

func (jd *JiraDir) Walk(user, name string) (trees.File, error) {

	if f, ok := jd.thing.(jiraWalker); ok {
		return f.Walk(jd.client, name)
	}
	if f, ok := jd.thing.(trees.Dir); ok {
		return f.Walk(user, name)
	}

	return nil, trees.ErrPermissionDenied
}

func (jd *JiraDir) List(user string) ([]qp.Stat, error) {
	if f, ok := jd.thing.(jiraLister); ok {
		return f.List(jd.client)
	}
	if f, ok := jd.thing.(trees.Lister); ok {
		return f.List(user)
	}

	return nil, trees.ErrPermissionDenied
}

func (jd *JiraDir) Remove(user, name string) error {
	if f, ok := jd.thing.(jiraRemover); ok {
		return f.Remove(jd.client, name)
	}
	if f, ok := jd.thing.(trees.Dir); ok {
		return f.Remove(user, name)
	}

	return trees.ErrPermissionDenied
}

func (jd *JiraDir) Create(user, name string, perms qp.FileMode) (trees.File, error) {
	return nil, trees.ErrPermissionDenied
}

func (jd *JiraDir) Open(user string, mode qp.OpenMode) (trees.ReadWriteAtCloser, error) {
	if !jd.CanOpen(user, mode) {
		return nil, errors.New("access denied")
	}

	jd.Lock()
	defer jd.Unlock()
	jd.Atime = time.Now()
	jd.Opens++
	return &trees.ListHandle{
		Dir:  jd,
		User: user,
	}, nil
}

func NewJiraDir(name string, perm qp.FileMode, user, group string, jc *Client, thing interface{}) (*JiraDir, error) {
	switch thing.(type) {
	case trees.Dir, jiraWalker, jiraLister, jiraRemover:
	default:
		return nil, fmt.Errorf("unsupported type: %T", thing)
	}

	return &JiraDir{
		thing:        thing,
		client:       jc,
		SyntheticDir: trees.NewSyntheticDir(name, perm, user, group),
	}, nil
}

type Client struct {
	user, pass string
	jiraURL    *url.URL
	cookies    []*http.Cookie
	usingOAuth bool
	*http.Client
}

func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	rel, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	u := c.jiraURL.ResolveReference(rel)

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	// Set session cookie if there is one
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}

	return req, nil
}

func (c *Client) Do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		return resp, fmt.Errorf("Error (status code %d): %s", resp.StatusCode, respBody)
	}

	if v != nil {
		// Open a NewDecoder and defer closing the reader only if there is a provided interface to decode to
		defer resp.Body.Close()
		err = json.Unmarshal(respBody, v)
	}

	return resp, err
}

func (c *Client) AcquireSessionCookie(username, password string) (bool, error) {
	apiEndpoint := "rest/auth/1/session"
	body := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		username,
		password,
	}

	req, err := c.NewRequest("POST", apiEndpoint, body)
	if err != nil {
		return false, err
	}

	resp, err := c.Do(req, nil)
	c.cookies = resp.Cookies()

	if err != nil {
		return false, fmt.Errorf("Auth at JIRA instance failed (HTTP(S) request). %s", err)
	}
	if resp != nil && resp.StatusCode != 200 {
		return false, fmt.Errorf("Auth at JIRA instance failed (HTTP(S) request). Status code: %d", resp.StatusCode)
	}

	return true, nil
}

func (c *Client) login() error {
	if c.usingOAuth {
		return nil
	}
	res, err := c.AcquireSessionCookie(c.user, c.pass)
	if err != nil || res == false {
		return fmt.Errorf("Could not authenticate to JIRA: %v\n", err)
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
