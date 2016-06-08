package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andygrunwald/go-jira"
	"github.com/joushou/qp"
	"github.com/joushou/qptools/fileserver/trees"
)

type CommentView struct {
	project string
	issueNo string
}

func (cw *CommentView) Walk(jc *Client, name string) (trees.File, error) {
	switch name {
	case "comment":
		sf := trees.NewSyntheticFile(name, 0777, "jira", "jira")
		onClose := func() error {
			sf.Lock()
			body := string(sf.Content)
			sf.Unlock()

			return AddComment(jc, fmt.Sprintf("%s-%s", cw.project, cw.issueNo), body)
		}
		return NewCloseSaver(sf, onClose), nil
	default:
		cmt, err := GetComment(jc, fmt.Sprintf("%s-%s", cw.project, cw.issueNo), name)
		if err != nil {
			return nil, err
		}
		if len(cmt.Body) > 0 && cmt.Body[len(cmt.Body)-1] != '\n' {
			cmt.Body += "\n"
		}

		sf := trees.NewSyntheticFile(name, 0777, cmt.Author.Name, "jira")
		sf.SetContent([]byte(cmt.Body))

		onClose := func() error {
			sf.Lock()
			body := string(sf.Content)
			sf.Unlock()

			return SetComment(jc, fmt.Sprintf("%s-%s", cw.project, cw.issueNo), name, body)
		}

		return NewCloseSaver(sf, onClose), nil
	}
}

func (cw *CommentView) List(jc *Client) ([]qp.Stat, error) {
	strs, err := GetCommentsForIssue(jc, fmt.Sprintf("%s-%s", cw.project, cw.issueNo))
	if err != nil {
		return nil, err
	}

	strs = append(strs, "comment")

	return StringsToStats(strs, 0777, "jira", "jira"), nil
}

func (cw *CommentView) Remove(jc *Client, name string) error {
	switch name {
	case "comment":
		return trees.ErrPermissionDenied
	default:
		return RemoveComment(jc, fmt.Sprintf("%s-%s", cw.project, cw.issueNo), name)
	}
}

type IssueView struct {
	project string
	issueNo string

	issueLock sync.Mutex
	newIssue  bool
	values    map[string]string
}

func (iw *IssueView) normalFiles() (files, dirs []string) {
	files = []string{"assignee", "creator", "ctl", "description", "type", "key", "reporter", "status",
		"summary", "labels", "transition", "priority", "resolution", "raw", "progress", "links", "components"}
	dirs = []string{"comments"}
	return
}

func (iw *IssueView) newFiles() (files, dirs []string) {
	files = []string{"ctl", "description", "type", "summary"}
	return
}

func (iw *IssueView) newWalk(jc *Client, file string) (trees.File, error) {
	files, dirs := iw.newFiles()
	if !StringExistsInSets(file, files, dirs) {
		return nil, nil
	}

	switch file {
	case "ctl":
		cmds := map[string]func([]string) error{
			"commit": func(args []string) error {
				var issuetype, summary, description string

				iw.issueLock.Lock()
				isNew := iw.newIssue
				if iw.values != nil {
					issuetype = strings.Replace(string(iw.values["type"]), "\n", "", -1)
					summary = strings.Replace(string(iw.values["summary"]), "\n", "", -1)
					description = strings.Replace(string(iw.values["description"]), "\n", "", -1)
				}
				iw.issueLock.Unlock()

				if !isNew {
					return errors.New("issue already committed")
				}

				issue := jira.Issue{
					Fields: &jira.IssueFields{
						Type: jira.IssueType{
							Name: issuetype,
						},
						Project: jira.Project{
							Key: iw.project,
						},
						Summary:     summary,
						Description: description,
					},
				}

				key, err := CreateIssue(jc, &issue)
				if err != nil {
					log.Printf("Create failed: %v", err)
					return err
				}

				keys := strings.Split(key, "-")
				if len(keys) != 2 {
					log.Printf("Weird key: %s", keys)
					return errors.New("weird key")
				}
				iw.issueLock.Lock()
				iw.issueNo = keys[1]
				iw.newIssue = false
				iw.issueLock.Unlock()
				return nil
			},
		}
		return NewCommandFile("ctl", 0777, "jira", "jira", cmds), nil
	default:
		sf := trees.NewSyntheticFile(file, 0777, "jira", "jira")
		iw.issueLock.Lock()
		defer iw.issueLock.Unlock()

		if iw.values == nil {
			iw.values = make(map[string]string)
		}

		value := iw.values[file]

		sf.SetContent([]byte(value))

		onClose := func() error {
			iw.issueLock.Lock()
			defer iw.issueLock.Unlock()

			iw.values[file] = string(sf.Content)
			return nil
		}

		return NewCloseSaver(sf, onClose), nil
	}

}

func renderIssueLink(l *jira.IssueLink, key string) string {
	switch {
	case l.OutwardIssue != nil:
		return fmt.Sprintf("%s %s %s", key, l.OutwardIssue.Key, l.Type.Name)
	case l.InwardIssue != nil:
		return fmt.Sprintf("%s %s %s", l.InwardIssue.Key, key, l.Type.Name)
	default:
		return ""
	}
}

func (iw *IssueView) normalWalk(jc *Client, file string) (trees.File, error) {
	files, dirs := iw.normalFiles()
	if !StringExistsInSets(file, files, dirs) {
		return nil, nil
	}

	issue, err := GetIssue(jc, fmt.Sprintf("%s-%s", iw.project, iw.issueNo))
	if err != nil {
		return nil, err
	}

	sf := trees.NewSyntheticFile(file, 0777, "jira", "jira")

	switch file {
	case "assignee":
		if issue.Fields != nil && issue.Fields.Assignee != nil {
			sf.SetContent([]byte(issue.Fields.Assignee.Name + "\n"))
		}
	case "reporter":
		if issue.Fields != nil && issue.Fields.Reporter != nil {
			sf.SetContent([]byte(issue.Fields.Reporter.Name + "\n"))
		}
	case "creator":
		if issue.Fields != nil && issue.Fields.Creator != nil {
			sf.SetContent([]byte(issue.Fields.Creator.Name + "\n"))
		}
	case "summary":
		if issue.Fields != nil {
			sf.SetContent([]byte(issue.Fields.Summary + "\n"))
		}
	case "description":
		if issue.Fields != nil {
			sf.SetContent([]byte(issue.Fields.Description + "\n"))
		}
	case "type":
		if issue.Fields != nil {
			sf.SetContent([]byte(issue.Fields.Type.Name + "\n"))
		}
	case "status":
		if issue.Fields != nil && issue.Fields.Status != nil {
			sf.SetContent([]byte(issue.Fields.Status.Name + "\n"))
		}
	case "priority":
		if issue.Fields != nil && issue.Fields.Priority != nil {
			sf.SetContent([]byte(issue.Fields.Priority.Name + "\n"))
		}
	case "resolution":
		if issue.Fields != nil && issue.Fields.Resolution != nil {
			sf.SetContent([]byte(issue.Fields.Resolution.Name + "\n"))
		}
	case "progress":
		if issue.Fields != nil && issue.Fields.Progress != nil {
			p := time.Duration(issue.Fields.Progress.Progress) * time.Second
			t := time.Duration(issue.Fields.Progress.Total) * time.Second
			r := t - p
			sf.SetContent([]byte(fmt.Sprintf("Progress: %v, Remaining: %v, Total: %v\n", p, r, t)))
		}
	case "key":
		sf.SetContent([]byte(issue.Key + "\n"))
	case "components":
		if issue.Fields != nil {
			var s string
			for _, comp := range issue.Fields.Components {
				s += comp.Name + "\n"
			}
			sf.SetContent([]byte(s))
		}
	case "labels":
		if issue.Fields != nil {
			var s string
			for _, lbl := range issue.Fields.Labels {
				s += lbl + "\n"
			}
			sf.SetContent([]byte(s))
		}
	case "transition":
		trs, err := GetTransitionsForIssue(jc, issue.Key)
		if err != nil {
			log.Printf("Could not get transitions for issue %s: %v", issue.Key, err)
			return nil, err
		}

		var s string
		for _, tr := range trs {
			s += tr.Name + "\n"
		}
		sf.SetContent([]byte(s))
	case "links":
		var s string
		if issue.Fields != nil {
			for _, l := range issue.Fields.IssueLinks {
				s += renderIssueLink(l, issue.Key) + "\n"
			}
		}
		sf.SetContent([]byte(s))
	case "comments":
		return NewJiraDir(file,
			0555|qp.DMDIR,
			"jira",
			"jira",
			jc,
			&CommentView{project: iw.project, issueNo: iw.issueNo})
	case "raw":
		b, err := json.MarshalIndent(issue, "", "   ")
		if err != nil {
			return nil, err
		}
		sf.SetContent(b)
	case "ctl":
		cmds := map[string]func([]string) error{
			"delete": func(args []string) error {
				return DeleteIssue(jc, issue.Key)
			},
		}
		return NewCommandFile("ctl", 0777, "jira", "jira", cmds), nil
	}

	onClose := func() error {
		switch file {
		case "key", "raw", "progress":
			return nil

		case "links":
			cur := make(map[string]string)
			for _, l := range issue.Fields.IssueLinks {
				cur[renderIssueLink(l, issue.Key)] = l.ID
			}

			sf.Lock()
			str := string(sf.Content)
			sf.Unlock()

			// Figure out which issue links are new, and which are old.
			var new []string
			input := strings.Split(str, "\n")
			for _, s := range input {
				if s == "" {
					continue
				}
				if _, exists := cur[s]; !exists {
					new = append(new, s)
				} else {
					delete(cur, s)
				}
			}

			// Delete the remaining old issue links
			for k, v := range cur {
				err := DeleteIssueLink(jc, v)
				if err != nil {
					log.Printf("Could not delete issue link %s (%s): %v", v, k, err)
				}
			}

			for _, k := range new {
				args := strings.Split(k, " ")
				if len(args) != 3 {
					continue
				}
				if args[0] != issue.Key && args[1] != issue.Key {
					continue
				}
				err := LinkIssues(jc, args[0], args[1], args[2])
				if err != nil {
					log.Printf("Could not create issue link (%s): %v", k, err)
				}
			}

			return nil
		case "transition":
			sf.Lock()
			str := string(sf.Content)
			sf.Unlock()
			str = strings.Replace(str, "\n", "", -1)

			return TransitionIssue(jc, issue.Key, str)

		case "status":
			sf.Lock()
			str := string(sf.Content)
			sf.Unlock()
			str = strings.Replace(str, "\n", "", -1)

			issue, err := GetIssue(jc, fmt.Sprintf("%s-%s", iw.project, iw.issueNo))
			if err != nil {
				log.Printf("Could not fetch issue: %v", err)
				return err
			}
			if issue.Fields == nil {
				log.Printf("Issue missing fields")
				return errors.New("oops")
			}
			if issue.Fields.Status == nil {
				log.Printf("Issue missing status")
				return errors.New("oops2")
			}

			wg, err := BuildWorkflow2(jc, iw.project, issue.Fields.Type.ID)
			if err != nil {
				log.Printf("Could not build workflow: %v", err)
				return err
			}

			p, err := wg.Path(issue.Fields.Status.Name, str, 500)
			if err != nil {
				log.Printf("Could not find path: %v", err)
				log.Printf("Workflow: \n%s\n", wg.Dump())
				return err
			}

			log.Printf("Workflow path: %s", strings.Join(p, ", "))

			for _, s := range p {
				err = TransitionIssue(jc, issue.Key, s)
				if err != nil {
					log.Printf("Could not transition issue: %v", err)
					return err
				}
			}

			return nil

		default:
			sf.Lock()
			str := string(sf.Content)
			sf.Unlock()
			switch file {
			case "description", "labels", "components":
			default:
				str = strings.Replace(str, "\n", "", -1)
			}
			return SetFieldInIssue(jc, issue.Key, file, str)
		}
	}

	return NewCloseSaver(sf, onClose), nil
}

func (iw *IssueView) Walk(jc *Client, file string) (trees.File, error) {
	iw.issueLock.Lock()
	isNew := iw.newIssue
	iw.issueLock.Unlock()

	if isNew {
		return iw.newWalk(jc, file)
	} else {
		return iw.normalWalk(jc, file)
	}
}

func (iw *IssueView) List(jc *Client) ([]qp.Stat, error) {
	iw.issueLock.Lock()
	isNew := iw.newIssue
	iw.issueLock.Unlock()

	var files, dirs []string
	if isNew {
		files, dirs = iw.newFiles()
	} else {
		files, dirs = iw.normalFiles()
	}
	var stats []qp.Stat

	stats = append(stats, StringsToStats(files, 0777, "jira", "jira")...)
	stats = append(stats, StringsToStats(dirs, 0777|qp.DMDIR, "jira", "jira")...)

	return stats, nil
}

type SearchView struct {
	query      string
	resultLock sync.Mutex
	results    []string
}

func (sw *SearchView) search(jc *Client) error {
	keys, err := GetKeysForSearch(jc, sw.query, jc.maxIssueListing)
	if err != nil {
		return err
	}

	sw.resultLock.Lock()
	sw.results = keys
	sw.resultLock.Unlock()
	return nil
}

func (sw *SearchView) Walk(jc *Client, file string) (trees.File, error) {
	sw.resultLock.Lock()
	keys := sw.results
	sw.resultLock.Unlock()

	if !StringExistsInSets(file, keys) {
		return nil, trees.ErrNoSuchFile
	}

	issue, err := GetIssue(jc, file)
	if err != nil {
		return nil, err
	}

	if issue.Fields == nil {
		return nil, errors.New("nil fields in issue")
	}

	s := strings.Split(issue.Key, "-")
	if len(s) != 2 {
		return nil, errors.New("funky issue key")
	}
	issueNo := s[1]

	iw := &IssueView{
		project: issue.Fields.Project.Key,
		issueNo: issueNo,
	}

	return NewJiraDir(file, 0555|qp.DMDIR, "jira", "jira", jc, iw)
}

func (sw *SearchView) List(jc *Client) ([]qp.Stat, error) {
	if err := sw.search(jc); err != nil {
		return nil, err
	}

	sw.resultLock.Lock()
	keys := sw.results
	sw.resultLock.Unlock()

	return StringsToStats(keys, 0555|qp.DMDIR, "jira", "jira"), nil
}

type ProjectView struct {
	project string
}

func (pw *ProjectView) Walk(jc *Client, issueNo string) (trees.File, error) {
	iw := &IssueView{
		project: pw.project,
	}

	if issueNo == "new" {
		iw.newIssue = true
	} else {
		// Check if the thing is a valid issue number.
		if _, err := strconv.ParseUint(issueNo, 10, 64); err != nil {
			return nil, nil
		}

		_, err := GetIssue(jc, fmt.Sprintf("%s-%s", pw.project, issueNo))
		if err != nil {
			log.Printf("Could not get issue details: %v", err)
			return nil, err
		}
		iw.issueNo = issueNo
	}

	return NewJiraDir(issueNo, 0555|qp.DMDIR, "jira", "jira", jc, iw)
}

func (pw *ProjectView) List(jc *Client) ([]qp.Stat, error) {
	keys, err := GetKeysForNIssues(jc, pw.project, jc.maxIssueListing)
	if err != nil {
		log.Printf("Could not generate issue list: %v", err)
		return nil, err
	}

	keys = append(keys, "new")
	return StringsToStats(keys, 0555|qp.DMDIR, "jira", "jira"), nil
}

type AllProjectsView struct{}

func (apw *AllProjectsView) Walk(jc *Client, projectName string) (trees.File, error) {
	projectName = strings.ToUpper(projectName)
	projects, err := GetProjects(jc)
	if err != nil {
		log.Printf("Could not generate project list: %v", err)
		return nil, err
	}

	pw := &ProjectView{project: projectName}

	for _, project := range projects {
		if project.Key == projectName {
			return NewJiraDir(projectName, 0555|qp.DMDIR, "jira", "jira", jc, pw)
		}
	}

	return nil, nil
}

func (apw *AllProjectsView) List(jc *Client) ([]qp.Stat, error) {
	projects, err := GetProjects(jc)
	if err != nil {
		log.Printf("Could not generate project list: %v", err)
		return nil, err
	}

	var strs []string
	for _, p := range projects {
		strs = append(strs, p.Key)
	}

	return StringsToStats(strs, 0555|qp.DMDIR, "jira", "jira"), nil
}

type JiraView struct {
	searchLock sync.Mutex
	searches   map[string]*SearchView
}

func (jw *JiraView) Walk(jc *Client, file string) (trees.File, error) {
	jw.searchLock.Lock()
	defer jw.searchLock.Unlock()
	if jw.searches == nil {
		jw.searches = make(map[string]*SearchView)
	}

	switch file {
	case "ctl":
		cmds := map[string]func([]string) error{
			"search": func(args []string) error {
				if len(args) < 2 {
					return errors.New("query missing")
				}

				sw := &SearchView{query: strings.Join(args[1:], " ")}
				if err := sw.search(jc); err != nil {
					log.Printf("search failed: %v", err)
					return err
				}

				jw.searchLock.Lock()
				jw.searches[args[0]] = sw
				jw.searchLock.Unlock()
				return nil
			},
			"pass-login": func(args []string) error {
				if len(args) == 2 {
					jc.user = args[0]
					jc.pass = args[1]
				}
				return jc.login()
			},
			"set": func(args []string) error {
				if len(args) != 2 {
					return errors.New("invalid arguments")
				}
				switch args[0] {
				case "max-issues":
					mi, err := strconv.ParseInt(args[1], 10, 64)
					if err != nil {
						return err
					}
					jc.maxIssueListing = int(mi)
					return nil
				default:
					return errors.New("unknown variable")
				}
			},
		}
		return NewCommandFile("ctl", 0777, "jira", "jira", cmds), nil
	case "projects":
		return NewJiraDir(file, 0555|qp.DMDIR, "jira", "jira", jc, &AllProjectsView{})
	default:
		search, exists := jw.searches[file]

		if !exists {
			return nil, nil
		}

		return NewJiraDir(file, 0555|qp.DMDIR, "jira", "jira", jc, search)
	}
}

func (jw *JiraView) List(jc *Client) ([]qp.Stat, error) {
	jw.searchLock.Lock()
	defer jw.searchLock.Unlock()
	if jw.searches == nil {
		jw.searches = make(map[string]*SearchView)
	}

	var strs []string
	for k := range jw.searches {
		strs = append(strs, k)
	}

	a := StringsToStats([]string{"projects"}, 0555|qp.DMDIR, "jira", "jira")
	b := StringsToStats([]string{"ctl"}, 0777, "jira", "jira")
	c := StringsToStats(strs, 0777|qp.DMDIR, "jira", "jira")
	return append(append(a, b...), c...), nil
}

func (jw *JiraView) Remove(jc *Client, file string) error {
	switch file {
	case "ctl", "projects":
		return trees.ErrPermissionDenied
	default:
		jw.searchLock.Lock()
		defer jw.searchLock.Unlock()
		if jw.searches == nil {
			jw.searches = make(map[string]*SearchView)
		}

		if _, exists := jw.searches[file]; exists {
			delete(jw.searches, file)
			return nil
		}

		return trees.ErrNoSuchFile
	}
}
