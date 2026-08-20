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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePublicKeyPEM generates a fresh RSA public key and writes it as
// PEM to the given path.
func writePublicKeyPEM(t *testing.T, path string) {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&raw.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
}

func TestKeyCache_CachesUnchangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0_keys")
	writePublicKeyPEM(t, path)

	cache := NewKeyCache()

	first, err := cache.Get(path)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}

	second, err := cache.Get(path)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}

	if first != second {
		t.Errorf("expected cached key set to be reused")
	}
}

func TestKeyCache_ReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0_keys")
	writePublicKeyPEM(t, path)

	cache := NewKeyCache()

	first, err := cache.Get(path)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}

	// Replace the file with a different key and advance the
	// modification time beyond file system granularity.
	writePublicKeyPEM(t, path)

	mtime := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("updating file times: %v", err)
	}

	second, err := cache.Get(path)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}

	if first == second {
		t.Errorf("expected changed key file to be reloaded")
	}
}

func TestKeyCache_SizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0_keys")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxKeyFileSize+1)), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	cache := NewKeyCache()

	if _, err := cache.Get(path); err == nil {
		t.Errorf("expected oversized key file to be rejected")
	}
}

func TestKeyCache_MissingFile(t *testing.T) {
	cache := NewKeyCache()

	if _, err := cache.Get(filepath.Join(t.TempDir(), "0_keys")); err == nil {
		t.Errorf("expected missing key file to result in an error")
	}
}

func TestServerConfig_GetKeySet_UsesCache(t *testing.T) {
	keyLocation := t.TempDir()
	writePublicKeyPEM(t, filepath.Join(keyLocation, "7_keys"))

	cfg := &ServerConfig{KeyLocation: keyLocation, KeyCache: NewKeyCache()}

	first, err := cfg.GetKeySet(7)
	if err != nil {
		t.Fatalf("first GetKeySet: %v", err)
	}

	second, err := cfg.GetKeySet(7)
	if err != nil {
		t.Fatalf("second GetKeySet: %v", err)
	}

	if first != second {
		t.Errorf("expected cached key set to be reused")
	}
}
