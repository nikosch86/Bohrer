package common

import (
	"sync"
	"testing"
	"time"
)

func TestWithReadLock(t *testing.T) {
	handler := &MutexHandler{}
	counter := 0
	
	// Test concurrent reads
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.WithReadLock(func() {
				// Simulate some work
				time.Sleep(10 * time.Millisecond)
				_ = counter // Read operation
			})
		}()
	}
	
	wg.Wait()
	// If we get here without deadlock, concurrent reads work
}

func TestWithWriteLock(t *testing.T) {
	handler := &MutexHandler{}
	counter := 0
	
	// Test concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.WithWriteLock(func() {
				counter++
			})
		}()
	}
	
	wg.Wait()
	
	if counter != 10 {
		t.Errorf("Expected counter to be 10, got %d", counter)
	}
}

func TestWithReadLockReturn(t *testing.T) {
	handler := &MutexHandler{}
	value := "test-value"
	
	result := handler.WithReadLockReturn(func() interface{} {
		return value
	})
	
	if result != value {
		t.Errorf("Expected %s, got %v", value, result)
	}
}

func TestWithWriteLockReturn(t *testing.T) {
	handler := &MutexHandler{}
	value := 42
	
	result := handler.WithWriteLockReturn(func() interface{} {
		return value
	})
	
	if result != value {
		t.Errorf("Expected %d, got %v", value, result)
	}
}

func TestMixedReadWrite(t *testing.T) {
	handler := &MutexHandler{}
	data := make(map[string]int)
	
	var wg sync.WaitGroup
	
	// Writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			handler.WithWriteLock(func() {
				data[string(rune('a'+idx))] = idx
			})
		}(i)
	}
	
	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.WithReadLock(func() {
				_ = len(data) // Read operation
			})
		}()
	}
	
	wg.Wait()
	
	// Verify all writes completed
	if len(data) != 5 {
		t.Errorf("Expected 5 entries in map, got %d", len(data))
	}
}

func TestDirectLockMethods(t *testing.T) {
	handler := &MutexHandler{}
	
	// Test write lock/unlock
	handler.Lock()
	handler.Unlock()
	
	// Test read lock/unlock
	handler.RLock()
	handler.RUnlock()
	
	// If we get here without deadlock, direct methods work
}

func TestConcurrentReadsDontBlock(t *testing.T) {
	handler := &MutexHandler{}
	done := make(chan bool, 2)
	
	// Start two concurrent reads
	go func() {
		handler.WithReadLock(func() {
			time.Sleep(50 * time.Millisecond)
			done <- true
		})
	}()
	
	go func() {
		handler.WithReadLock(func() {
			time.Sleep(50 * time.Millisecond)
			done <- true
		})
	}()
	
	// Both should complete in ~50ms if running concurrently
	timeout := time.After(80 * time.Millisecond)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
			// Good
		case <-timeout:
			t.Fatal("Concurrent reads blocked each other")
		}
	}
}

func TestWriteBlocksReads(t *testing.T) {
	handler := &MutexHandler{}
	writeStarted := make(chan bool)
	readBlocked := false
	
	// Start a write that takes some time
	go func() {
		handler.WithWriteLock(func() {
			writeStarted <- true
			time.Sleep(50 * time.Millisecond)
		})
	}()
	
	<-writeStarted
	
	// Try to read - should block until write completes
	start := time.Now()
	handler.WithReadLock(func() {
		elapsed := time.Since(start)
		if elapsed >= 40*time.Millisecond {
			readBlocked = true
		}
	})
	
	if !readBlocked {
		t.Error("Read should have been blocked by write")
	}
}