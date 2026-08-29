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
	path    string
	current atomic.Pointer[Policy]
}

// missing file loads as an empty policy that denies nothing; invalid file errors
func NewManager(path string) (*Manager, error) {
	m := &Manager{path: path}
	p, err := load(path)
	if err != nil {
		return nil, err
	}
	m.current.Store(p)
	return m, nil
}

func load(path string) (*Policy, error) {
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
	return p, nil
}

func (m *Manager) Current() *Policy { return m.current.Load() }

func (m *Manager) Reload() error {
	newPolicy, err := load(m.path)
	if err != nil {
		return err
	}
	old := m.current.Swap(newPolicy)
	time.AfterFunc(closeGrace, old.Close)
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
