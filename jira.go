package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/andygrunwald/go-jira"
	"github.com/joushou/qp"
	"github.com/joushou/qptools/fileserver/trees"
)

type jiraWalker interface {
	Walk(jc *jira.Client, name string) (trees.File, error)
}

type jiraLister interface {
	List(jc *jira.Client) ([]qp.Stat, error)
}

type jiraRemover interface {
	Remove(jc *jira.Client, name string) error
}

type CommentView struct {
	project string
	issueNo string
}

func (cw *CommentView) Walk(jc *jira.Client, name string) (trees.File, error) {
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

func (cw *CommentView) List(jc *jira.Client) ([]qp.Stat, error) {
	strs, err := GetCommentsForIssue(jc, fmt.Sprintf("%s-%s", cw.project, cw.issueNo))
	if err != nil {
		return nil, err
	}

	strs = append(strs, "comment")

	return StringsToStats(strs, 0777, "jira", "jira"), nil
}

func (cw *CommentView) Remove(jc *jira.Client, name string) error {
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
	files = []string{"assignee", "creator", "ctl", "description", "issuetype", "key", "reporter", "status", "summary", "labels", "transitions"}
	dirs = []string{"comments"}
	return
}

func (iw *IssueView) newFiles() (files, dirs []string) {
	files = []string{"ctl", "description", "issuetype", "summary"}
	return
}

func (iw *IssueView) newWalk(jc *jira.Client, file string) (trees.File, error) {
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
					issuetype = strings.Replace(string(iw.values["issuetype"]), "\n", "", -1)
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

func (iw *IssueView) normalWalk(jc *jira.Client, file string) (trees.File, error) {
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
	case "issuetype":
		if issue.Fields != nil {
			sf.SetContent([]byte(issue.Fields.Type.Name + "\n"))
		}
	case "status":
		if issue.Fields != nil && issue.Fields.Status != nil {
			sf.SetContent([]byte(issue.Fields.Status.Name + "\n"))
		}
	case "key":
		sf.SetContent([]byte(issue.Key + "\n"))
	case "labels":
		if issue.Fields != nil {
			var s string
			for _, lbl := range issue.Fields.Labels {
				s += lbl + "\n"
			}
			sf.SetContent([]byte(s))
		}
	case "transitions":
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
	case "comments":
		return NewJiraDir(file,
			0555|qp.DMDIR,
			"jira",
			"jira",
			jc,
			&CommentView{project: iw.project, issueNo: iw.issueNo})
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
		case "key":
			return nil
		case "status", "transitions":
			sf.Lock()
			str := string(sf.Content)
			sf.Unlock()
			str = strings.Replace(str, "\n", "", -1)

			return TransitionIssue(jc, issue.Key, str)
		default:
			sf.Lock()
			str := string(sf.Content)
			sf.Unlock()
			if file != "description" && file != "labels" {
				str = strings.Replace(str, "\n", "", -1)
			}
			return SetFieldInIssue(jc, issue.Key, file, str)
		}
	}

	return NewCloseSaver(sf, onClose), nil
}

func (iw *IssueView) Walk(jc *jira.Client, file string) (trees.File, error) {
	iw.issueLock.Lock()
	isNew := iw.newIssue
	iw.issueLock.Unlock()

	if isNew {
		return iw.newWalk(jc, file)
	} else {
		return iw.normalWalk(jc, file)
	}
}

func (iw *IssueView) List(jc *jira.Client) ([]qp.Stat, error) {
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

type ProjectView struct {
	project string
}

func (pw *ProjectView) Walk(jc *jira.Client, issueNo string) (trees.File, error) {
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
			return nil, err
		}
		iw.issueNo = issueNo
	}

	return NewJiraDir(issueNo, 0555|qp.DMDIR, "jira", "jira", jc, iw)
}

func (pw *ProjectView) List(jc *jira.Client) ([]qp.Stat, error) {
	keys, err := GetKeysForNIssues(jc, pw.project, 250)
	if err != nil {
		return nil, err
	}

	keys = append(keys, "new")
	return StringsToStats(keys, 0555|qp.DMDIR, "jira", "jira"), nil
}

type JiraView struct{}

func (jw *JiraView) Walk(jc *jira.Client, projectName string) (trees.File, error) {
	projectName = strings.ToUpper(projectName)
	projects, err := GetProjects(jc)
	if err != nil {
		return nil, err
	}

	for _, project := range projects {
		if project.Key == projectName {
			goto found
		}
	}

	return nil, nil

found:

	return NewJiraDir(projectName,
		0555|qp.DMDIR,
		"jira",
		"jira",
		jc,
		&ProjectView{project: projectName})
}

func (jw *JiraView) List(jc *jira.Client) ([]qp.Stat, error) {
	projects, err := GetProjects(jc)
	if err != nil {
		return nil, err
	}

	var strs []string
	for _, p := range projects {
		strs = append(strs, p.Key)
	}

	return StringsToStats(strs, 0555|qp.DMDIR, "jira", "jira"), nil
}
