// Package logger provides OWNTRACE's leveled, redaction-aware logger.
//
// All output passes through the redaction layer before it reaches a sink, and
// credential-bearing fields are never accepted as structured input; callers
// that hold secrets must use the *WithSecret methods or simply not log them.
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/redact"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	default:
		return "ERROR"
	}
}

// ParseLevel maps a config string to a Level; unknown values fall back to info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger is safe for concurrent use.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	file  *os.File
	level Level
	quiet bool // stderr suppressed (used for --output json runs)
}

// New builds a logger writing to stderr at the given level.
func New(level Level) *Logger {
	return &Logger{out: os.Stderr, level: level}
}

// OpenFile additionally tees log output into a session log file. The file is
// created with 0600 permissions because logs may contain sensitive context.
func (l *Logger) OpenFile(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.file = f
	return nil
}

// Close releases the log file, if any.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

// SetQuiet suppresses stderr output (machine-readable mode).
func (l *Logger) SetQuiet(q bool) { l.mu.Lock(); l.quiet = q; l.mu.Unlock() }

func (l *Logger) logf(level Level, format string, args ...any) {
	if level < l.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	msg = redact.Text(msg)
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " " + level.String() + " " + msg + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.quiet && l.out != nil {
		_, _ = io.WriteString(l.out, line)
	}
	if l.file != nil {
		_, _ = io.WriteString(l.file, line)
	}
}

func (l *Logger) Debugf(f string, a ...any) { l.logf(LevelDebug, f, a...) }
func (l *Logger) Infof(f string, a ...any)  { l.logf(LevelInfo, f, a...) }
func (l *Logger) Warnf(f string, a ...any)  { l.logf(LevelWarn, f, a...) }
func (l *Logger) Errorf(f string, a ...any) { l.logf(LevelError, f, a...) }
