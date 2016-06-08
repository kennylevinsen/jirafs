package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/joushou/qp"
	"github.com/joushou/qptools/fileserver/trees"
)

type jiraWalker interface {
	Walk(jc *Client, name string) (trees.File, error)
}

type jiraLister interface {
	List(jc *Client) ([]qp.Stat, error)
}

type jiraRemover interface {
	Remove(jc *Client, name string) error
}

// JiraDir is a convenience wrapper for dynamic directory hooks.
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

// CloseSaver calls a callback on save if the file was opened for writing.
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

// CommandFile calls commands on write.
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
