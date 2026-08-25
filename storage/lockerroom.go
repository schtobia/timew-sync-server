/*
Copyright 2020 - 2021, Jan Bormet, Anna-Felicitas Hausmann, Joachim Schmidt, Vincent Stollenwerk, Arne Turuc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package storage

import (
	"sync"
	"time"
)

const cleanupDelay = 5 * time.Second

type lockEntry struct {
	mu   sync.Mutex
	refs int
}

// A LockerRoom is a collection of Mutexes mapped to user ids.
type LockerRoom struct {
	globalLock sync.Mutex
	locks      map[UserID]*lockEntry
}

// InitializeLockerRoom sets up this LockerRoom instance.
func (lr *LockerRoom) InitializeLockerRoom() {
	lr.locks = make(map[UserID]*lockEntry)
}

// Lock acquires the lock for this user id.
func (lr *LockerRoom) Lock(userID UserID) {
	entry := lr.getOrCreateEntry(userID)
	entry.mu.Lock()
}

// Unlock releases the lock for this user id.
func (lr *LockerRoom) Unlock(userID UserID) {
	lr.globalLock.Lock()
	entry := lr.locks[userID]
	entry.refs--
	lr.globalLock.Unlock()

	entry.mu.Unlock()
	lr.scheduleCleanup(userID)
}

func (lr *LockerRoom) getOrCreateEntry(userID UserID) *lockEntry {
	lr.globalLock.Lock()
	defer lr.globalLock.Unlock()

	if lr.locks[userID] == nil {
		lr.locks[userID] = &lockEntry{refs: 1} //nolint:exhaustruct // sync.Mutex has zero value
	} else {
		lr.locks[userID].refs++
	}

	return lr.locks[userID]
}

func (lr *LockerRoom) scheduleCleanup(userID UserID) {
	time.AfterFunc(cleanupDelay, func() {
		lr.globalLock.Lock()
		defer lr.globalLock.Unlock()

		entry := lr.locks[userID]
		if entry != nil && entry.refs == 0 {
			delete(lr.locks, userID)
		}
	})
}
