package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/andygrunwald/go-jira"
)

type thing struct {
	Name string `json:"name"`
}

func BuildWorkflow1(jc *jira.Client, project, issueTypeNo string) (*WorkflowGraph, error) {
	req, err := jc.NewRequest("GET", fmt.Sprintf("/rest/projectconfig/latest/issuetype/%s/%s/workflow", project, issueTypeNo), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA 1: %v", err)
	}

	var t thing
	if _, err = jc.Do(req, &t); err != nil {
		return nil, fmt.Errorf("could not query JIRA 2: %v", err)
	}

	req, err = jc.NewRequest("GET", fmt.Sprintf("/rest/projectconfig/latest/workflow?workflowName=%s", url.QueryEscape(t.Name)), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA 3: %v", err)
	}

	var wr WorkflowResponse1
	if _, err = jc.Do(req, &wr); err != nil {
		return nil, fmt.Errorf("could not query JIRA 4: %v", err)
	}

	var wg WorkflowGraph
	wg.Build1(&wr)
	return &wg, nil
}

func BuildWorkflow2(jc *jira.Client, project, issueTypeNo string) (*WorkflowGraph, error) {
	req, err := jc.NewRequest("GET", fmt.Sprintf("/rest/projectconfig/latest/issuetype/%s/%s/workflow", project, issueTypeNo), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA 1: %v", err)
	}

	var t thing
	if _, err = jc.Do(req, &t); err != nil {
		return nil, fmt.Errorf("could not query JIRA 2: %v", err)
	}

	req, err = jc.NewRequest("GET", fmt.Sprintf("/rest/workflowDesigner/latest/workflows?name=%s", url.QueryEscape(t.Name)), nil)
	if err != nil {
		return nil, fmt.Errorf("could not query JIRA 3: %v", err)
	}

	req.Header.Set("X-Atlassian-Token", "nocheck")

	var wr WorkflowResponse2
	if _, err = jc.Do(req, &wr); err != nil {
		return nil, fmt.Errorf("could not query JIRA 4: %v", err)
	}

	var wg WorkflowGraph
	wg.Build2(&wr)
	return &wg, nil
}

type WorkflowResponse2 struct {
	Layout struct {
		Statuses []struct {
			ID           string `json:"statusId"`
			TransitionID string `json:"id"`
			Name         string `json:"name"`
			Description  string `json:"description"`
			Initial      bool   `json:"initial"`
		} `json:"statuses"`
		Transitions []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			SourceID    string `json:"sourceId"`
			TargetID    string `json:"targetId"`
			ActionID    int    `json:"actionId"`
			Global      bool   `json:"globalTransition"`
			Looped      bool   `json:"loopedTransition"`
		} `json:"transitions"`
	} `json:"layout"`
}

type WorkflowResponse1 struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ID          int    `json:"id"`
	DisplayName string `json:"displayName"`
	Admin       bool   `json:"admin"`
	Sources     []struct {
		FromStatus WorkflowStatus `json:"fromStatus"`
		Targets    []struct {
			ToStatus       WorkflowStatus `json:"toStatus"`
			TransitionName string
		} `json:"targets"`
	} `json:"sources"`
}

type WorkflowStatus struct {
	StatusCategory struct {
		Sequence       int      `json:"sequence"`
		PrimaryAlias   string   `json:"primaryAlias"`
		TranslatedName string   `json:"translatedName"`
		ColorName      string   `json:"colorName"`
		Aliases        []string `json:"aliases"`
		Name           string   `json:"name"`
		Key            string   `json:"key"`
		ID             int      `json:"id"`
	} `json:"statusCategory"`
	IconURL     string `json:"iconUrl"`
	Description string `json:"description"`
	Name        string `json:"name"`
	ID          string `json:"id"`
}

func (wf *WorkflowStatus) Status() *Status {
	return &Status{
		Name:        wf.Name,
		ID:          wf.ID,
		Description: wf.Description,
	}
}

type Status struct {
	Name        string
	Description string
	ID          string
	Edges       []StatusEdge
}

type StatusEdge struct {
	Name   string
	Status *Status
}

type WorkflowGraph struct {
	// verteces is a map of lower-cased status named to their status struct.
	verteces map[string]*Status
}

func (wg *WorkflowGraph) Build2(wr *WorkflowResponse2) {
	if wg.verteces == nil {
		wg.verteces = make(map[string]*Status)
	}

	local := make(map[string]*Status)
	layout := wr.Layout

	for _, s := range layout.Statuses {
		l := &Status{
			Name:        s.Name,
			Description: s.Description,
			ID:          s.ID,
		}

		wg.verteces[strings.ToLower(s.Name)] = l
		local[s.TransitionID] = l
	}

	for _, t := range layout.Transitions {
		a := local[t.SourceID]
		b := local[t.TargetID]
		edge := StatusEdge{
			Name:   t.Name,
			Status: b,
		}
		if t.Global {
			for _, v := range local {
				v.Edges = append(v.Edges, edge)
			}
		} else {
			a.Edges = append(a.Edges, edge)
		}
	}
}

func (wg *WorkflowGraph) Build1(wr *WorkflowResponse1) {
	if wg.verteces == nil {
		wg.verteces = make(map[string]*Status)
	}
	for _, elem := range wr.Sources {
		name := strings.ToLower(elem.FromStatus.Name)
		fromStatus, exists := wg.verteces[name]
		if !exists {
			fromStatus = elem.FromStatus.Status()
			wg.verteces[name] = fromStatus
		}

		for _, target := range elem.Targets {
			targetName := strings.ToLower(target.ToStatus.Name)
			targetStatus, exists := wg.verteces[targetName]
			if !exists {
				targetStatus = target.ToStatus.Status()
				wg.verteces[name] = targetStatus
			}
			targetEdge := StatusEdge{
				Name:   target.TransitionName,
				Status: targetStatus,
			}

			fromStatus.Edges = append(fromStatus.Edges, targetEdge)
		}
	}
}

func (wg *WorkflowGraph) Dump() string {
	var ss string
	for _, v := range wg.verteces {
		var s string
		for _, e := range v.Edges {
			s += fmt.Sprintf("%s (%s), ", e.Status.Name, e.Name)
		}
		ss += fmt.Sprintf("Status: %s, edges: %s\n", v.Name, s)
	}

	return ss
}

type path struct {
	from *path
	edge StatusEdge
}

// Path finds the shortest path in the workflow graph from A to B, searching at
// most limit verteces. A negative limit results in path executing without a
// limit. Cycles are detected and terminated, so the limit is just to avoid high
// searching times in *very* large graphs. A and B are case insensitive for
// convenience.
func (wg *WorkflowGraph) Path(A, B string, limit int) ([]string, error) {
	statusA := wg.verteces[strings.ToLower(A)]
	statusB := wg.verteces[strings.ToLower(B)]

	if statusA == nil || statusB == nil {
		return nil, errors.New("no such status")
	}

	visited := make(map[string]bool)

	var search []path
	for _, edge := range statusA.Edges {
		search = append(search, path{edge: edge})
	}

	for len(search) > 0 {
		limit--
		if limit == 0 {
			break
		}
		p := search[0]
		search = search[1:]

		// FOUND!
		if p.edge.Status == statusB {
			var s []string
			start := &p

			for {
				s = append([]string{start.edge.Name}, s...)
				if start.from == nil {
					break
				}

				start = start.from
			}
			return s, nil
		}

		if visited[p.edge.Status.ID] {
			// We have already walked all edges of this vertice.
			continue
		}
		visited[p.edge.Status.ID] = true

		// Add the edges to the search.
		for _, edge := range p.edge.Status.Edges {
			search = append(search, path{from: &p, edge: edge})
		}
	}

	return nil, errors.New("path not found")
}
