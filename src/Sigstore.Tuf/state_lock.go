package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const stateLockFileName = "state.lock"

type stateLock struct {
	file *os.File
}

func acquireStateLock(
	statePath string,
	timeout time.Duration,
	operation string,
) (*stateLock, error) {
	path := filepath.Join(statePath, stateLockFileName)
	started := time.Now()
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open shared Sigstore state lock: %w", err)
		}
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			owner := struct {
				SchemaVersion int       `json:"schemaVersion"`
				ProcessID     int       `json:"processId"`
				Operation     string    `json:"operation"`
				AcquiredAtUTC time.Time `json:"acquiredAtUtc"`
			}{
				SchemaVersion: 1,
				ProcessID:     os.Getpid(),
				Operation:     operation,
				AcquiredAtUTC: time.Now().UTC(),
			}
			data, marshalErr := json.Marshal(owner)
			if marshalErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("marshal Sigstore state lock owner: %w", marshalErr)
			}
			data = append(data, '\n')
			if truncateErr := file.Truncate(0); truncateErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("truncate Sigstore state lock owner: %w", truncateErr)
			}
			if _, seekErr := file.Seek(0, 0); seekErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("seek Sigstore state lock owner: %w", seekErr)
			}
			if _, writeErr := file.Write(data); writeErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("write Sigstore state lock owner: %w", writeErr)
			}
			if syncErr := file.Sync(); syncErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("sync Sigstore state lock owner: %w", syncErr)
			}
			return &stateLock{file: file}, nil
		}
		_ = file.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) &&
			!errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("acquire shared Sigstore state lock: %w", err)
		}
		if time.Since(started) >= timeout {
			owner, _ := os.ReadFile(path)
			return nil, fmt.Errorf(
				"Sigstore state at %s is locked by another operation (last owner metadata: %s); the operating-system lock is released automatically when its owner exits",
				statePath,
				owner,
			)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (lock *stateLock) release() {
	_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	_ = lock.file.Close()
}
