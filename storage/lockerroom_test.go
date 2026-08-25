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
	"testing"
	"time"
)

func TestLockerRoom_CleanupAfterUnlock(t *testing.T) {
	lr := &LockerRoom{}
	lr.InitializeLockerRoom()

	userID := UserID(42)
	lr.Lock(userID)
	lr.Unlock(userID)

	time.Sleep(cleanupDelay + 100*time.Millisecond)

	lr.globalLock.Lock()
	_, exists := lr.locks[userID]
	lr.globalLock.Unlock()

	if exists {
		t.Error("expected entry to be cleaned up after unlock")
	}
}

func TestLockerRoom_NoCleanupWhileLocked(t *testing.T) {
	lr := &LockerRoom{}
	lr.InitializeLockerRoom()

	userID := UserID(42)
	lr.Lock(userID)

	time.Sleep(cleanupDelay + 100*time.Millisecond)

	lr.globalLock.Lock()
	_, exists := lr.locks[userID]
	lr.globalLock.Unlock()

	if !exists {
		t.Error("expected entry to exist while lock is held")
	}

	lr.Unlock(userID)
}

func TestLockerRoom_NoCleanupWhileWaiting(t *testing.T) {
	lr := &LockerRoom{}
	lr.InitializeLockerRoom()

	userID := UserID(42)
	lr.Lock(userID)

	var wg sync.WaitGroup

	wg.Go(func() {
		lr.Lock(userID)

		lr.Unlock(userID)
	})

	time.Sleep(100 * time.Millisecond)
	lr.Unlock(userID)
	wg.Wait()

	time.Sleep(cleanupDelay + 100*time.Millisecond)

	lr.globalLock.Lock()
	_, exists := lr.locks[userID]
	lr.globalLock.Unlock()

	if exists {
		t.Error("expected entry to be cleaned up after all locks released")
	}
}

func TestLockerRoom_MultipleUsers(t *testing.T) {
	lr := &LockerRoom{}
	lr.InitializeLockerRoom()

	user1 := UserID(1)
	user2 := UserID(2)

	lr.Lock(user1)
	lr.Lock(user2)
	lr.Unlock(user1)

	time.Sleep(cleanupDelay + 100*time.Millisecond)

	lr.globalLock.Lock()
	_, user1Exists := lr.locks[user1]
	_, user2Exists := lr.locks[user2]
	lr.globalLock.Unlock()

	if user1Exists {
		t.Error("expected user1 entry to be cleaned up")
	}

	if !user2Exists {
		t.Error("expected user2 entry to still exist")
	}

	lr.Unlock(user2)
}
