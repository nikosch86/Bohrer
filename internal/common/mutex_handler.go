// Package common provides shared utilities and patterns used across the application
package common

import (
	"sync"
)

// MutexHandler provides a base struct with thread-safe operations
type MutexHandler struct {
	mutex sync.RWMutex
}

// WithReadLock executes a function while holding a read lock
func (m *MutexHandler) WithReadLock(fn func()) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	fn()
}

// WithWriteLock executes a function while holding a write lock
func (m *MutexHandler) WithWriteLock(fn func()) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	fn()
}

// WithReadLockReturn executes a function while holding a read lock and returns a value
func (m *MutexHandler) WithReadLockReturn(fn func() interface{}) interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return fn()
}

// WithWriteLockReturn executes a function while holding a write lock and returns a value
func (m *MutexHandler) WithWriteLockReturn(fn func() interface{}) interface{} {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return fn()
}

// Lock acquires the write lock
func (m *MutexHandler) Lock() {
	m.mutex.Lock()
}

// Unlock releases the write lock
func (m *MutexHandler) Unlock() {
	m.mutex.Unlock()
}

// RLock acquires the read lock
func (m *MutexHandler) RLock() {
	m.mutex.RLock()
}

// RUnlock releases the read lock
func (m *MutexHandler) RUnlock() {
	m.mutex.RUnlock()
}