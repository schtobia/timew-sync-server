/*
Copyright 2021 - Jan Bormet, Anna-Felicitas Hausmann, Joachim Schmidt, Vincent Stollenwerk, Arne Turuc

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

package sync

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// maxKeyFileSize limits the size of key files to protect against
// resource exhaustion through oversized files. 1 MiB leaves ample
// room for any realistic number of keys per user.
const maxKeyFileSize = 1 << 20

// errKeyFileTooLarge indicates a key file that exceeds maxKeyFileSize.
var errKeyFileTooLarge = errors.New("key file exceeds the maximum allowed size")

// keyCacheEntry is a cached key set together with the file metadata
// used to detect changes.
type keyCacheEntry struct {
	modTime time.Time
	size    int64
	keySet  jwk.Set
}

// KeyCache caches parsed key sets per key file so that unchanged files
// are only read and parsed once. Entries are invalidated when the file
// modification time or size changes.
type KeyCache struct {
	mu      sync.Mutex
	entries map[string]keyCacheEntry
}

// NewKeyCache creates an empty key cache.
func NewKeyCache() *KeyCache {
	return &KeyCache{ //nolint:exhaustruct // mu is a usable zero-value mutex
		entries: make(map[string]keyCacheEntry),
	}
}

// Get returns the key set stored in the file at the given path.
// Unchanged files are only read and parsed once; modified files are
// loaded again.
//
//nolint:ireturn // returning the jwk.Set interface is idiomatic for the JWX library
func (c *KeyCache) Get(path string) (jwk.Set, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("accessing key file: %w", err)
	}

	if info.Size() > maxKeyFileSize {
		return nil, errKeyFileTooLarge
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[path]; ok && entry.modTime.Equal(info.ModTime()) && entry.size == info.Size() {
		return entry.keySet, nil
	}

	keySet, err := loadKeySet(path)
	if err != nil {
		return nil, fmt.Errorf("loading key file: %w", err)
	}

	c.entries[path] = keyCacheEntry{modTime: info.ModTime(), size: info.Size(), keySet: keySet}

	return keySet, nil
}
