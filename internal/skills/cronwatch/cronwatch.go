package cronwatch

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/fsnotify/fsnotify"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 520
	SkillName = "cron-watch"
)

// defaultWatchPaths are Debian's cron and at locations, as shipped in the YAML
var defaultWatchPaths = []string{
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.monthly",
	"/etc/cron.weekly",
	"/var/spool/cron/crontabs",
	"/var/spool/cron/atjobs",
}

// settle is how long a path must be quiet before it is checked. Editors,
// crontab(1) and dpkg write a temporary file and rename it into place, so
// one change is several inotify events.
var settle = time.Second

const (
	// maxRead caps how much of a file is read to compare and quote it
	maxRead = 1 << 20

	// maxQuoted is how many added lines an alert quotes
	maxQuoted = 3
)

// CronWatch alerts on cron and at jobs being added, changed or removed
type CronWatch struct {
	mu         sync.RWMutex
	enabled    bool
	config     map[string]interface{}
	watchPaths []string
	dpkgLocks  []string
}

// New creates a CronWatch with default config (used by daemon registry).
func New() *CronWatch {
	return &CronWatch{
		watchPaths: defaultWatchPaths,
		dpkgLocks:  skills.DpkgLocks,
	}
}

// NewFromConfig creates a CronWatch pre-populated from a SkillConfig (used by CLI enabler).
func NewFromConfig(cfg skills.SkillConfig) *CronWatch {
	c := New()
	if cfg.Config != nil {
		c.Configure(cfg.Config)
	}
	return c
}

func (c *CronWatch) ID() int      { return SkillID }
func (c *CronWatch) Name() string { return SkillName }
func (c *CronWatch) Description() string {
	return "Monitor cron and at job locations with inotify for new, changed or removed jobs"
}
func (c *CronWatch) Why() string {
	return "Persistence via scheduled tasks is a standard post-exploitation technique. Attackers add cron or at jobs to maintain access and run periodic tasks."
}
func (c *CronWatch) Requires() []string       { return []string{"inotify"} }
func (c *CronWatch) Tags() []string           { return []string{"persistence", "cron", "at"} }
func (c *CronWatch) DropIns() []skills.DropIn { return nil }
func (c *CronWatch) SetupHints() []string     { return nil }
func (c *CronWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}
func (c *CronWatch) CheckSystemState() (bool, error) { return true, nil }

func (c *CronWatch) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

func (c *CronWatch) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

func (c *CronWatch) Config() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

func (c *CronWatch) Configure(cfg map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = cfg

	// A watch_paths removed from the config on reload goes back to the default
	c.watchPaths = defaultWatchPaths
	if raw, ok := cfg["watch_paths"]; ok {
		list, ok := raw.([]interface{})
		if !ok {
			return fmt.Errorf("watch_paths must be a list of paths")
		}
		paths := make([]string, 0, len(list))
		for _, p := range list {
			s, ok := p.(string)
			if !ok {
				return fmt.Errorf("watch_paths entries must be strings, got %T", p)
			}
			if !filepath.IsAbs(s) {
				return fmt.Errorf("watch path %q must be absolute", s)
			}
			paths = append(paths, filepath.Clean(s))
		}
		c.watchPaths = paths
	}
	return nil
}

// entry is what was last seen at a path
type entry struct {
	dir  bool
	mode os.FileMode
	uid  uint32
	// link is a symlink's target. cron reads through a symlink in its
	// directories, so a link to a world-writable file is a job anyone can edit.
	link string
	sum  [sha256.Size]byte
	// lines are the file's non-blank, non-comment lines: the jobs in a
	// crontab, the commands in a cron.daily script
	lines []string
}

// same reports whether nothing that matters to cron changed: the content,
// the owner (cron runs a spool crontab as its owner) or the mode (run-parts
// only runs executable scripts)
func (e entry) same(o entry) bool {
	return e.dir == o.dir && e.mode == o.mode && e.uid == o.uid && e.link == o.link && e.sum == o.sum
}

// readEntry reads what is at path now. ok is false if there is nothing there.
// follow is for the configured paths, which may be symlinks to where the
// system keeps its cron files; an entry in a watched directory is reported as
// the symlink it is.
func readEntry(path string, follow bool) (entry, bool) {
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	info, err := stat(path)
	if err != nil {
		return entry{}, false
	}
	e := entry{dir: info.IsDir(), mode: info.Mode()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		e.uid = st.Uid
	}
	if info.Mode()&os.ModeSymlink != 0 {
		e.link, _ = os.Readlink(path)
	} else if !info.Mode().IsRegular() {
		return e, true
	}

	// The file can be swapped between the stat and the open: don't follow a
	// symlink that wasn't one a moment ago, and don't block on a FIFO
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if e.link == "" && !follow {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		// A dangling link, or unreadable: compare on what was stat'ed alone
		if e.link == "" {
			log.Printf("[cron-watch] Can't read %q: %v", path, err)
		}
		return e, true
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return e, true
	}
	data, _ := io.ReadAll(io.LimitReader(f, maxRead))
	e.sum = sha256.Sum256(data)
	e.lines = jobLines(string(data))
	return e, true
}

// jobLines returns the lines of a crontab or script that do something
func jobLines(content string) []string {
	var lines []string
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// added returns the lines in cur that weren't in old
func added(old, cur []string) []string {
	had := make(map[string]int, len(old))
	for _, l := range old {
		had[l]++
	}
	var out []string
	for _, l := range cur {
		if had[l] > 0 {
			had[l]--
			continue
		}
		out = append(out, l)
	}
	return out
}

// ignoredName reports whether a file in a watched directory is one no
// scheduler runs, on Debian's cron and run-parts or on cronie: dotfiles (at's
// .SEQ counter, editor swap files) and name~ backups. Only names every one of
// them skips can be ignored: cronie runs /etc/cron.d/x.dpkg-new, for one.
func ignoredName(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~")
}

// atRunning reports whether path is an at job being run: atd renames a job to
// =<job> in its spool while it runs. Anywhere else = is an ordinary name, and
// cronie runs /etc/cron.d/=x.
func atRunning(path string) bool {
	switch filepath.Base(filepath.Dir(path)) {
	case "atjobs", "at":
		return strings.HasPrefix(filepath.Base(path), "=")
	}
	return false
}

// watcher holds the state of one Watch run
type watcher struct {
	c         *CronWatch
	fs        *fsnotify.Watcher
	paths     map[string]bool // configured paths
	snapshot  map[string]entry
	pending   map[string]pendingChange
	dpkgLocks []string
}

// pendingChange is a path with events not yet checked
type pendingChange struct {
	last time.Time
	// dpkg is whether a package run was in progress at any of its events
	dpkg bool
}

// Watch watches the configured paths and the directories holding them with
// inotify, and alerts once a changed path has settled
func (c *CronWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	c.mu.RLock()
	paths, locks := c.watchPaths, c.dpkgLocks
	c.mu.RUnlock()

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating inotify watcher: %w", err)
	}

	w := &watcher{
		c:         c,
		fs:        fsw,
		paths:     make(map[string]bool, len(paths)),
		snapshot:  make(map[string]entry),
		pending:   make(map[string]pendingChange),
		dpkgLocks: locks,
	}
	for _, p := range paths {
		w.paths[p] = true
	}

	watching := 0
	for _, p := range paths {
		if w.add(p) {
			watching++
		}
	}
	if watching == 0 {
		fsw.Close()
		return nil, fmt.Errorf("none of the watch_paths can be watched: their directories don't exist")
	}
	log.Printf("[cron-watch] Watching %d of %d paths, %d files known", watching, len(paths), len(w.snapshot))

	alerts := make(chan notifier.Alert, 10)
	go w.loop(ctx, alerts)
	return alerts, nil
}

// add watches a configured path: the directory holding it, so the path being
// created, replaced or removed is seen, and the path itself if it is a
// directory. Whatever is there now goes in the snapshot.
func (w *watcher) add(path string) bool {
	parent := filepath.Dir(path)
	if err := w.fs.Add(parent); err != nil {
		log.Printf("[cron-watch] Not watching %s: can't watch %s: %v", path, parent, err)
		return false
	}

	e, ok := readEntry(path, true)
	if !ok {
		log.Printf("[cron-watch] %s doesn't exist yet; watching for it", path)
		return true
	}
	w.snapshot[path] = e
	if e.dir {
		w.addDir(path)
	}
	return true
}

// addDir watches a configured directory and records what's in it
func (w *watcher) addDir(dir string) {
	if err := w.fs.Add(dir); err != nil {
		log.Printf("[cron-watch] Can't watch %s: %v", dir, err)
		return
	}
	for _, p := range w.listDir(dir) {
		if e, ok := readEntry(p, false); ok {
			w.snapshot[p] = e
		}
	}
}

// listDir returns the entries in dir that a scheduler could run
func (w *watcher) listDir(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, de := range ents {
		p := filepath.Join(dir, de.Name())
		if !ignoredName(de.Name()) && !atRunning(p) {
			out = append(out, p)
		}
	}
	return out
}

// relevant reports whether an event on path concerns a configured path or
// an entry in a configured directory
func (w *watcher) relevant(path string) bool {
	if w.paths[path] {
		return true
	}
	return w.paths[filepath.Dir(path)] && !ignoredName(filepath.Base(path)) && !atRunning(path)
}

func (w *watcher) loop(ctx context.Context, alerts chan<- notifier.Alert) {
	defer close(alerts)
	defer w.fs.Close()

	tick := time.NewTicker(settle / 2)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case ev, ok := <-w.fs.Events:
			if !ok {
				return
			}
			w.event(ev)

		case err, ok := <-w.fs.Errors:
			if !ok {
				return
			}
			log.Printf("[cron-watch] inotify error: %v", err)
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				// Events were lost: check everything against the snapshot
				w.markAll()
			}

		case now := <-tick.C:
			for _, a := range w.flush(now) {
				select {
				case alerts <- a:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (w *watcher) event(ev fsnotify.Event) {
	path := filepath.Clean(ev.Name)
	if !w.relevant(path) {
		return
	}
	w.mark(path)

	// A configured directory removed, moved away or replaced: what was in it
	// is gone, or must be compared with what is in the new one
	if w.paths[path] {
		for p := range w.snapshot {
			if filepath.Dir(p) == path {
				w.mark(p)
			}
		}
	}

	// A configured directory created (or moved into place) after startup
	if w.paths[path] && ev.Has(fsnotify.Create) {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			log.Printf("[cron-watch] %s appeared; watching it", path)
			if err := w.fs.Add(path); err != nil {
				log.Printf("[cron-watch] Can't watch %s: %v", path, err)
			}
			for _, p := range w.listDir(path) {
				w.mark(p)
			}
		}
	}
}

func (w *watcher) mark(path string) {
	pc := w.pending[path]
	pc.last = time.Now()
	pc.dpkg = pc.dpkg || skills.DpkgRunning(w.dpkgLocks)
	w.pending[path] = pc
}

// markAll queues every known and present path for checking
func (w *watcher) markAll() {
	for p := range w.snapshot {
		w.mark(p)
	}
	for p := range w.paths {
		w.mark(p)
		for _, child := range w.listDir(p) {
			w.mark(child)
		}
	}
}

// flush checks the paths that have been quiet for settle and returns alerts
// for those that changed, in path order
func (w *watcher) flush(now time.Time) []notifier.Alert {
	var ready []string
	for p, pc := range w.pending {
		if now.Sub(pc.last) >= settle {
			ready = append(ready, p)
		}
	}
	sort.Strings(ready)

	var out []notifier.Alert
	for _, p := range ready {
		pc := w.pending[p]
		delete(w.pending, p)

		old, had := w.snapshot[p]
		cur, exists := readEntry(p, w.paths[p])
		if exists {
			w.snapshot[p] = cur
		} else {
			delete(w.snapshot, p)
		}

		if a, ok := w.c.classify(p, old, had, cur, exists, pc.dpkg); ok {
			log.Printf("[cron-watch] %s: %s", a.Title, a.Activity)
			out = append(out, a)
		}
	}
	return out
}

// classify compares what was at path with what is there now
func (c *CronWatch) classify(path string, old entry, had bool, cur entry, exists, dpkg bool) (notifier.Alert, bool) {
	var title, verb string
	severity := notifier.SeverityContact
	switch {
	case !had && !exists:
		// A temporary file, created and renamed or removed in one go
		return notifier.Alert{}, false
	case had && exists && old.same(cur):
		// Touched or rewritten unchanged
		return notifier.Alert{}, false
	case !had:
		title, verb = "New Scheduled Job", "New"
	case !exists:
		// An at job is removed once it has run
		title, verb = "Scheduled Job Removed", "Removed"
		severity = notifier.SeverityMovement
	default:
		title, verb = "Scheduled Job Changed", "Changed"
	}

	e := cur
	if !exists {
		e = old
	}
	kind := "file"
	switch {
	case e.dir:
		kind = "directory"
	case e.link != "":
		kind = "symlink"
	}

	equip := "inotify"
	switch {
	case !exists:
		if !old.dir {
			equip = fmt.Sprintf("%d lines removed", len(old.lines))
		}
	case cur.dir:
	default:
		var details []string
		if cur.link != "" && cur.link != old.link {
			details = append(details, "→ "+clean(cur.link))
		}
		if lines := added(old.lines, cur.lines); len(lines) > 0 {
			details = append(details, quote(lines))
		} else if had && old.sum != cur.sum {
			details = append(details, "no lines added")
		}
		if had && old.mode != cur.mode {
			details = append(details, fmt.Sprintf("mode %s → %s", old.mode, cur.mode))
		}
		if had && old.uid != cur.uid {
			details = append(details, fmt.Sprintf("owner %s → %s", userName(old.uid), userName(cur.uid)))
		}
		if len(details) > 0 {
			equip = strings.Join(details, "; ")
		}
	}

	unit := "owner unknown"
	if exists {
		unit = "owner " + userName(cur.uid)
	} else if had {
		unit = "was owned by " + userName(old.uid)
	}

	// Packages install and update cron jobs as a matter of course;
	// pkg-monitor reports the package change itself
	if dpkg {
		severity = notifier.SeverityMovement
		unit += "; dpkg was running"
	}

	return notifier.Alert{
		Severity:  severity,
		SkillID:   SkillID,
		SkillName: SkillName,
		Title:     title,
		Size:      "1 " + kind,
		Activity:  fmt.Sprintf("%s %s: %s", verb, kind, clean(filepath.Base(path))),
		Location:  clean(path),
		Unit:      unit,
		Time:      time.Now(),
		Equipment: equip,
		Metadata: map[string]string{
			"path":  clean(path),
			"kind":  kind,
			"event": strings.ToLower(verb),
			"dpkg":  strconv.FormatBool(dpkg),
		},
	}, true
}

// quote returns the first few added lines for the alert
func quote(lines []string) string {
	shown := lines
	if len(shown) > maxQuoted {
		shown = shown[:maxQuoted]
	}
	parts := make([]string, len(shown))
	for i, l := range shown {
		if r := []rune(l); len(r) > 200 {
			l = string(r[:200]) + "…"
		}
		parts[i] = "+ " + clean(l)
	}
	s := strings.Join(parts, " | ")
	if more := len(lines) - len(shown); more > 0 {
		s += fmt.Sprintf(" (and %d more)", more)
	}
	return s
}

// clean replaces anything in a name or line that isn't plainly visible text:
// they come from whoever wrote the file, and a newline would forge a log line
// or a right-to-left override disguise the command an alert quotes
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || (unicode.IsGraphic(r) && !unicode.Is(unicode.Cf, r)) {
			return r
		}
		return '?'
	}, strings.ToValidUTF8(s, "?"))
}

// userName returns "name (uid=N)", or just the uid if it has no name
func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return fmt.Sprintf("%s (uid=%s)", u.Username, id)
	}
	return "uid=" + id
}
