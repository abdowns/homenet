package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// grace period before freeing a superseded policy's compiled program, so an
// in flight request still evaluating against it doesn't hit freed memory
const closeGrace = 10 * time.Second

type Manager struct {
	path       string
	current    atomic.Pointer[Policy]
	currentSrc atomic.Pointer[string]
}

// missing file loads as an empty policy that denies nothing; invalid file errors
func NewManager(path string) (*Manager, error) {
	m := &Manager{path: path}
	src, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("policy: reading %s: %w", path, err)
		}
		src = nil
	}
	p, err := Compile(string(src))
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	m.current.Store(p)
	srcStr := string(src)
	m.currentSrc.Store(&srcStr)
	return m, nil
}

func (m *Manager) Current() *Policy { return m.current.Load() }

func (m *Manager) Source() string { return *m.currentSrc.Load() }

func (m *Manager) Reload() error {
	src, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			src = nil // removed file reverts to a policy that denies nothing
		} else {
			return fmt.Errorf("policy: reading %s: %w", m.path, err)
		}
	}
	newPolicy, err := Compile(string(src))
	if err != nil {
		return fmt.Errorf("policy: %s: %w", m.path, err)
	}
	old := m.current.Swap(newPolicy)
	time.AfterFunc(closeGrace, old.Close)
	srcStr := string(src)
	m.currentSrc.Store(&srcStr)
	return nil
}

// writes only after a successful compile, via tmp file plus rename, so a
// concurrent watch triggered reload never sees a partial write
func (m *Manager) Apply(src string) error {
	p, err := Compile(src)
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		p.Close()
		return fmt.Errorf("policy: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		p.Close()
		return fmt.Errorf("policy: renaming %s to %s: %w", tmp, m.path, err)
	}
	old := m.current.Swap(p)
	time.AfterFunc(closeGrace, old.Close)
	srcCopy := src
	m.currentSrc.Store(&srcCopy)
	return nil
}

func (m *Manager) Watch(stop <-chan struct{}) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("policy: starting file watcher: %w", err)
	}
	defer watcher.Close()

	// watch the dir, not the file: editors replace files via a
	// temp write plus rename, which a watch on the file's inode misses
	dir := filepath.Dir(m.path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("policy: watching %s: %w", dir, err)
	}
	target := filepath.Clean(m.path)

	for {
		select {
		case <-stop:
			return nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if filepath.Clean(ev.Name) != target {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			if err := m.Reload(); err != nil {
				log.Printf("policy: reload failed, keeping previous policy: %v", err)
			} else {
				log.Printf("policy: reloaded %s", m.path)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("policy: watch error: %v", err)
		}
	}
}
