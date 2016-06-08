package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/andygrunwald/go-jira"
	"github.com/joushou/qp"
)

type SearchResult struct {
	Issues []jira.Issue `json:"issues"`
}

func GetProjects(jc *Client) ([]jira.Project, error) {
	var projects []jira.Project
	if err := jc.RPC("GET", "/rest/api/2/project", nil, &projects); err != nil {
		return nil, fmt.Errorf("could not query projects: %v", err)
	}
	return projects, nil
}

func GetTypesForProject(jc *Client, project string) ([]string, error) {
	var types []jira.IssueType
	if err := jc.RPC("GET", "/rest/api/2/issuetype", nil, &types); err != nil {
		return nil, fmt.Errorf("could not query issue types: %v", err)
	}

	ss := make([]string, len(types))
	for i, tp := range types {
		ss[i] = tp.Name
	}

	return ss, nil
}

func GetKeysForSearch(jc *Client, query string, max int) ([]string, error) {
	var s SearchResult
	url := fmt.Sprintf("/rest/api/2/search?fields=key&maxResults=%d&jql=%s", max, url.QueryEscape(query))
	if err := jc.RPC("GET", url, nil, &s); err != nil {
		return nil, fmt.Errorf("could not execute search: %v", err)
	}

	ss := make([]string, len(s.Issues))
	for i, issue := range s.Issues {
		ss[i] = issue.Key
	}

	return ss, nil
}

func GetKeysForNIssues(jc *Client, project string, max int) ([]string, error) {
	var s SearchResult
	url := fmt.Sprintf("/rest/api/2/search?fields=key&maxResults=%d&jql=project=%s", max, project)
	if err := jc.RPC("GET", url, nil, &s); err != nil {
		return nil, fmt.Errorf("could not execute search: %v", err)
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
	var i jira.Issue
	url := fmt.Sprintf("/rest/api/2/issue/%s", key)
	if err := jc.RPC("GET", url, nil, &i); err != nil {
		return nil, fmt.Errorf("could not query issue: %v", err)
	}
	return &i, nil
}

type CreateIssueResult struct {
	ID  string `json:"id,omitempty"`
	Key string `json:"key,omitempty"`
}

func CreateIssue(jc *Client, issue *jira.Issue) (string, error) {
	var cir CreateIssueResult
	if err := jc.RPC("POST", "/rest/api/2/issue", issue, &cir); err != nil {
		return "", fmt.Errorf("could not create issue: %v", err)
	}
	return cir.Key, nil
}

func DeleteIssue(jc *Client, issue string) error {
	url := fmt.Sprintf("/rest/api/2/issue/%s", issue)
	if err := jc.RPC("DELETE", url, nil, nil); err != nil {
		return fmt.Errorf("could not delete issue: %v", err)
	}
	return nil
}

func DeleteIssueLink(jc *Client, issueLinkID string) error {
	url := fmt.Sprintf("/rest/api/2/issueLink/%s", issueLinkID)
	if err := jc.RPC("DELETE", url, nil, nil); err != nil {
		return fmt.Errorf("could not delete issue link: %v", err)
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

	if err := jc.RPC("POST", "/rest/api/2/issueLink", issueLink, nil); err != nil {
		return fmt.Errorf("could not create issue link: %v", err)
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
	var tr TransitionResult
	url := fmt.Sprintf("/rest/api/2/issue/%s/transitions", issue)
	if err := jc.RPC("GET", url, nil, &tr); err != nil {
		return nil, fmt.Errorf("could not get transitions: %v", err)
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
	url := fmt.Sprintf("/rest/api/2/issue/%s/transitions", issue)
	if err := jc.RPC("POST", url, post, nil); err != nil {
		return fmt.Errorf("could not transition issue: %v", err)
	}
	return nil
}

func SetFieldInIssue(jc *Client, issue, field, val string) error {
	switch field {
	case "type":
		field = "issuetype"
	}

	url := fmt.Sprintf("/rest/api/2/issue/%s", issue)
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

	if err := jc.RPC(method, url, post, nil); err != nil {
		return fmt.Errorf("could not set field for issue: %v", err)
	}
	return nil
}

type CommentResult struct {
	Comments []jira.Comment `json:"comments,omitempty"`
}

func GetCommentsForIssue(jc *Client, issue string) ([]string, error) {
	var cr CommentResult
	url := fmt.Sprintf("/rest/api/2/issue/%s/comment?maxResults=1000", issue)
	if err := jc.RPC("GET", url, nil, &cr); err != nil {
		return nil, fmt.Errorf("could not get comments: %v", err)
	}

	var ss []string
	for _, c := range cr.Comments {
		ss = append(ss, c.ID)
	}

	return ss, nil
}

func GetComment(jc *Client, issue, id string) (*jira.Comment, error) {
	var c jira.Comment
	url := fmt.Sprintf("/rest/api/2/issue/%s/comment/%s", issue, id)
	if err := jc.RPC("GET", url, nil, &c); err != nil {
		return nil, fmt.Errorf("could not get comment: %v", err)
	}
	return &c, nil
}

func SetComment(jc *Client, issue, id, body string) error {
	c := jira.Comment{
		Body: body,
	}
	url := fmt.Sprintf("/rest/api/2/issue/%s/comment/%s", issue, id)
	if err := jc.RPC("PUT", url, c, nil); err != nil {
		return fmt.Errorf("could not set comment: %v", err)
	}
	return nil
}

func AddComment(jc *Client, issue, body string) error {
	c := jira.Comment{
		Body: body,
	}
	url := fmt.Sprintf("/rest/api/2/issue/%s/comment/", issue)
	if err := jc.RPC("POST", url, c, nil); err != nil {
		return fmt.Errorf("could not add comment: %v", err)
	}
	return nil
}

func RemoveComment(jc *Client, issue, id string) error {
	url := fmt.Sprintf("/rest/api/2/issue/%s/comment/%s", issue, id)
	if err := jc.RPC("DELETE", url, nil, nil); err != nil {
		return fmt.Errorf("could not delete comment: %v", err)
	}
	return nil
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
