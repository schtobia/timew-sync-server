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
)

// A LockerRoom is a collection of Mutexes mapped to user ids.
type LockerRoom struct {
	globalLock sync.Mutex
	locks      map[UserID]*sync.Mutex
}

// InitializeLockerRoom sets up this LockerRoom instance.
func (lr *LockerRoom) InitializeLockerRoom() {
	lr.locks = make(map[UserID]*sync.Mutex)
}

// Lock acquires the lock for this user id.
func (lr *LockerRoom) Lock(userID UserID) {
	lr.createUserIfNotExists(userID)

	lr.locks[userID].Lock()
}

// Unlock releases the lock for this user id.
func (lr *LockerRoom) Unlock(userID UserID) {
	lr.locks[userID].Unlock()
}

// createUserIfNotExists creates an entry into the locks map if the user does not exist yet.
func (lr *LockerRoom) createUserIfNotExists(userID UserID) {
	lr.globalLock.Lock()
	defer lr.globalLock.Unlock()

	if lr.locks[userID] == nil {
		lr.locks[userID] = &sync.Mutex{}
	}
}
