package frp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultLogMaxFileBytes  int64 = 2 * 1024 * 1024
	defaultLogMaxFiles            = 5
	defaultLogMaxTotalBytes int64 = 8 * 1024 * 1024
	minimumLogMaxFileBytes  int64 = 512
)

// LogRetention bounds the active FRP log and its rotated files. MaxFiles
// includes the active file. MaxTotalBytes includes all retained files.
type LogRetention struct {
	MaxFileBytes  int64
	MaxFiles      int
	MaxTotalBytes int64
}

type LogFileSummary struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
	Current    bool      `json:"current"`
}

// LogStorageStatus is safe to include in diagnostics. LastError reports a
// persistent-write, rotation, retention, or path-safety failure without
// preventing the in-memory log ring from continuing to work.
type LogStorageStatus struct {
	Directory     string           `json:"directory"`
	ActivePath    string           `json:"active_path"`
	MaxFileBytes  int64            `json:"max_file_bytes"`
	MaxFiles      int              `json:"max_files"`
	MaxTotalBytes int64            `json:"max_total_bytes"`
	TotalBytes    int64            `json:"total_bytes"`
	Files         []LogFileSummary `json:"files"`
	LastError     string           `json:"last_error,omitempty"`
	LastErrorAt   time.Time        `json:"last_error_at,omitempty"`
	Closed        bool             `json:"closed"`
}

func defaultLogRetention() LogRetention {
	return LogRetention{
		MaxFileBytes:  defaultLogMaxFileBytes,
		MaxFiles:      defaultLogMaxFiles,
		MaxTotalBytes: defaultLogMaxTotalBytes,
	}
}

func normalizeLogRetention(retention LogRetention) LogRetention {
	if retention.MaxFileBytes <= 0 {
		retention.MaxFileBytes = defaultLogMaxFileBytes
	}
	if retention.MaxFileBytes < minimumLogMaxFileBytes {
		retention.MaxFileBytes = minimumLogMaxFileBytes
	}
	if retention.MaxFiles <= 0 {
		retention.MaxFiles = defaultLogMaxFiles
	}
	if retention.MaxTotalBytes <= 0 {
		retention.MaxTotalBytes = defaultLogMaxTotalBytes
	}
	if retention.MaxTotalBytes < retention.MaxFileBytes {
		retention.MaxTotalBytes = retention.MaxFileBytes
	}
	return retention
}

type persistentLog struct {
	mu sync.Mutex

	storeRoot  string
	dir        string
	activePath string
	retention  LogRetention
	initErr    error

	file       *os.File
	closed     bool
	lastErr    error
	lastErrAt  time.Time
	knownFiles int
	knownTotal int64
}

func newPersistentLog(storeRoot string, retention LogRetention) *persistentLog {
	root, err := filepath.Abs(storeRoot)
	if err != nil {
		return &persistentLog{retention: normalizeLogRetention(retention), initErr: fmt.Errorf("resolve FRP store root: %w", err)}
	}
	root = filepath.Clean(root)
	dir := filepath.Join(root, logsDirName)
	active := filepath.Join(dir, frpLogFileName)
	if !pathWithinRoot(root, dir) || !pathWithinRoot(dir, active) {
		return &persistentLog{
			storeRoot: root, dir: dir, activePath: active, retention: normalizeLogRetention(retention),
			initErr: fmt.Errorf("FRP log path escapes the profile store: %s", active),
		}
	}
	return &persistentLog{
		storeRoot: root, dir: dir, activePath: active,
		retention: normalizeLogRetention(retention),
	}
}

func (p *persistentLog) write(line string) {
	if p == nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	record := time.Now().UTC().Format(time.RFC3339Nano) + " " + line + "\n"
	record = boundLogRecord(record, p.retention.MaxFileBytes)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.initErr != nil {
		p.recordErrorLocked(p.initErr)
		return
	}
	if err := p.ensureOpenLocked(); err != nil {
		p.recordErrorLocked(err)
		return
	}
	info, err := p.file.Stat()
	if err != nil {
		p.closeFileLocked()
		p.recordErrorLocked(fmt.Errorf("stat active FRP log: %w", err))
		return
	}
	rotated := false
	if info.Size() > 0 && info.Size()+int64(len(record)) > p.retention.MaxFileBytes {
		if err = p.rotateLocked(); err != nil {
			p.recordErrorLocked(err)
			return
		}
		rotated = true
	}
	written, err := io.WriteString(p.file, record)
	if err != nil {
		p.closeFileLocked()
		p.recordErrorLocked(fmt.Errorf("write active FRP log: %w", err))
		return
	}
	p.knownTotal += int64(written)
	if rotated {
		p.knownFiles++
	}
	if rotated || p.knownFiles > p.retention.MaxFiles || p.knownTotal > p.retention.MaxTotalBytes {
		if err = p.pruneLocked(); err != nil {
			p.recordErrorLocked(err)
			return
		}
	}
	p.lastErr = nil
}

func (p *persistentLog) close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	closeErr := p.syncCloseFileLocked()
	if closeErr != nil {
		p.recordErrorLocked(fmt.Errorf("flush and close active FRP log: %w", closeErr))
	}
	return closeErr
}

func (p *persistentLog) status() LogStorageStatus {
	status := LogStorageStatus{}
	if p == nil {
		return status
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	status.Directory = p.dir
	status.ActivePath = p.activePath
	status.MaxFileBytes = p.retention.MaxFileBytes
	status.MaxFiles = p.retention.MaxFiles
	status.MaxTotalBytes = p.retention.MaxTotalBytes
	status.Closed = p.closed
	if p.lastErr != nil {
		status.LastError = p.lastErr.Error()
		status.LastErrorAt = p.lastErrAt
	}
	if p.initErr != nil {
		if status.LastError == "" {
			status.LastError = p.initErr.Error()
		}
		return status
	}
	files, total, err := p.scanLocked()
	if err != nil {
		if status.LastError == "" {
			status.LastError = err.Error()
		}
		return status
	}
	p.knownFiles = len(files)
	p.knownTotal = total
	status.Files = files
	status.TotalBytes = total
	return status
}

func (p *persistentLog) ensureOpenLocked() error {
	if p.file != nil {
		return nil
	}
	if err := p.ensureDirectoryLocked(); err != nil {
		return err
	}
	if info, err := os.Lstat(p.activePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing unsafe FRP log file %s", p.activePath)
		}
		if err = secureFile(p.activePath); err != nil {
			return fmt.Errorf("secure FRP log file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect FRP log file: %w", err)
	}
	file, err := os.OpenFile(p.activePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open FRP log file: %w", err)
	}
	if err = secureFile(p.activePath); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure FRP log file: %w", err)
	}
	files, total, err := p.scanLocked()
	if err != nil {
		_ = file.Close()
		return err
	}
	p.file = file
	p.knownFiles = len(files)
	p.knownTotal = total
	return nil
}

func (p *persistentLog) ensureDirectoryLocked() error {
	if err := ensurePrivateDirectory(p.storeRoot); err != nil {
		return fmt.Errorf("prepare FRP store root: %w", err)
	}
	if !pathWithinRoot(p.storeRoot, p.dir) {
		return fmt.Errorf("FRP log directory escapes the profile store")
	}
	if err := ensurePrivateDirectory(p.dir); err != nil {
		return fmt.Errorf("prepare FRP log directory: %w", err)
	}
	return nil
}

func (p *persistentLog) rotateLocked() error {
	if err := p.syncCloseFileLocked(); err != nil {
		return fmt.Errorf("flush and close FRP log before rotation: %w", err)
	}
	maxFiles := p.retention.MaxFiles
	if maxFiles > 1 {
		oldest := maxFiles - 1
		if err := p.removeLogPathLocked(p.rotatedPath(oldest)); err != nil {
			return err
		}
		for index := oldest - 1; index >= 1; index-- {
			source := p.rotatedPath(index)
			target := p.rotatedPath(index + 1)
			if err := p.renameLogPathLocked(source, target); err != nil {
				return err
			}
		}
		if err := p.renameLogPathLocked(p.activePath, p.rotatedPath(1)); err != nil {
			return err
		}
	} else if err := p.removeLogPathLocked(p.activePath); err != nil {
		return err
	}
	if err := p.openActiveLocked(); err != nil {
		return fmt.Errorf("reopen FRP log after rotation: %w", err)
	}
	return nil
}

func (p *persistentLog) openActiveLocked() error {
	file, err := os.OpenFile(p.activePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create active FRP log: %w", err)
	}
	if err = secureFile(p.activePath); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure active FRP log: %w", err)
	}
	p.file = file
	return nil
}

func (p *persistentLog) pruneLocked() error {
	files, total, err := p.scanLocked()
	if err != nil {
		return err
	}
	for len(files) > p.retention.MaxFiles || total > p.retention.MaxTotalBytes {
		oldest := -1
		for index := len(files) - 1; index >= 0; index-- {
			if !files[index].Current {
				oldest = index
				break
			}
		}
		if oldest < 0 {
			break
		}
		removed := files[oldest]
		if err = p.removeLogPathLocked(removed.Path); err != nil {
			return err
		}
		total -= removed.SizeBytes
		files = append(files[:oldest], files[oldest+1:]...)
	}
	p.knownFiles = len(files)
	p.knownTotal = total
	if len(files) > p.retention.MaxFiles || total > p.retention.MaxTotalBytes {
		return fmt.Errorf("FRP log retention could not be enforced: files=%d total=%d", len(files), total)
	}
	return nil
}

func (p *persistentLog) scanLocked() ([]LogFileSummary, int64, error) {
	dirInfo, err := os.Lstat(p.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("inspect FRP log directory: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return nil, 0, fmt.Errorf("refusing unsafe FRP log directory %s", p.dir)
	}
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return nil, 0, fmt.Errorf("scan FRP log directory: %w", err)
	}
	files := make([]LogFileSummary, 0, len(entries))
	var total int64
	for _, entry := range entries {
		index, ok := logFileIndex(entry.Name())
		if !ok {
			continue
		}
		path := filepath.Join(p.dir, entry.Name())
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return nil, 0, fmt.Errorf("inspect FRP log %s: %w", path, infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("refusing unsafe FRP log entry %s", path)
		}
		files = append(files, LogFileSummary{
			Name: entry.Name(), Path: path, SizeBytes: info.Size(), ModifiedAt: info.ModTime(), Current: index == 0,
		})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool {
		left, _ := logFileIndex(files[i].Name)
		right, _ := logFileIndex(files[j].Name)
		return left < right
	})
	return files, total, nil
}

func (p *persistentLog) removeLogPathLocked(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect FRP log for removal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove unsafe FRP log entry %s", path)
	}
	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove FRP log %s: %w", path, err)
	}
	return nil
}

func (p *persistentLog) renameLogPathLocked(source, target string) error {
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect FRP log for rotation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to rotate unsafe FRP log entry %s", source)
	}
	if err = p.removeLogPathLocked(target); err != nil {
		return err
	}
	if err = os.Rename(source, target); err != nil {
		return fmt.Errorf("rotate FRP log %s to %s: %w", source, target, err)
	}
	return nil
}

func (p *persistentLog) syncCloseFileLocked() error {
	if p.file == nil {
		return nil
	}
	file := p.file
	p.file = nil
	return errors.Join(file.Sync(), file.Close())
}

func (p *persistentLog) closeFileLocked() {
	if p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
}

func (p *persistentLog) recordErrorLocked(err error) {
	if err == nil {
		return
	}
	p.lastErr = err
	p.lastErrAt = time.Now().UTC()
}

func (p *persistentLog) rotatedPath(index int) string {
	return fmt.Sprintf("%s.%d", p.activePath, index)
}

func logFileIndex(name string) (int, bool) {
	if name == frpLogFileName {
		return 0, true
	}
	prefix := frpLogFileName + "."
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	suffix := strings.TrimPrefix(name, prefix)
	index, err := strconv.Atoi(suffix)
	if err != nil || index <= 0 || strconv.Itoa(index) != suffix {
		return 0, false
	}
	return index, true
}

func boundLogRecord(record string, limit int64) string {
	if limit <= 0 || int64(len(record)) <= limit {
		return record
	}
	suffix := " ...[truncated]\n"
	if int64(len(suffix)) >= limit {
		return record[:limit]
	}
	cut := int(limit) - len(suffix)
	for cut > 0 && !utf8.ValidString(record[:cut]) {
		cut--
	}
	return record[:cut] + suffix
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing unsafe private directory %s", path)
	}
	return secureDirectory(path)
}

func pathWithinRoot(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(rootAbs), filepath.Clean(candidateAbs))
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
