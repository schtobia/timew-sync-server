/*
Copyright 2020 <COPYRIGHT HOLDER>

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

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr replaced by a pipe and returns
// whatever the function wrote to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	oldStderr := os.Stderr
	os.Stderr = w

	defer func() { os.Stderr = oldStderr }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy pipe: %v", err)
	}

	return buf.String()
}

func TestRealMain_NoArgs(t *testing.T) {
	out := captureStderr(t, func() {
		if code := realMain([]string{"timew-sync-server"}); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
	if !strings.Contains(out, "Use commands") {
		t.Errorf("expected usage hint on stderr, got %q", out)
	}
}

func TestRealMain_VersionFlag(t *testing.T) {
	out := captureStderr(t, func() {
		if code := realMain([]string{"timew-sync-server", "--version"}); code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if !strings.Contains(out, version) {
		t.Errorf("expected version %q in stderr, got %q", version, out)
	}
}

func TestRealMain_UnknownCommand(t *testing.T) {
	out := captureStderr(t, func() {
		// --version is parsed by the default branch's flag set; an unknown
		// positional command without --version falls through to the
		// "Use commands" hint with exit code 1.
		if code := realMain([]string{"timew-sync-server", "frobnicate"}); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
	if !strings.Contains(out, "Use commands") {
		t.Errorf("expected usage hint on stderr, got %q", out)
	}
}

func TestRunAddKey_MissingPath(t *testing.T) {
	out := captureStderr(t, func() {
		if code := runAddKey([]string{"--id", "0"}); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
	if !strings.Contains(out, "Provide a key file") {
		t.Errorf("expected missing-path hint, got %q", out)
	}
}

func TestRunAddKey_NegativeUserID(t *testing.T) {
	out := captureStderr(t, func() {
		if code := runAddKey([]string{"--path", "/dev/null", "--id", "-1"}); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
	if !strings.Contains(out, "non-negative user id") {
		t.Errorf("expected negative-user-id hint, got %q", out)
	}
}

func TestRunAddKey_UnknownUser(t *testing.T) {
	// Use a fresh temp dir as keys-location so the user id definitely
	// does not exist there.
	tmp := t.TempDir()

	out := captureStderr(t, func() {
		if code := runAddKey([]string{"--path", "/dev/null", "--id", "9999", "--keys-location", tmp}); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})
	if !strings.Contains(out, "does not exist") {
		t.Errorf("expected 'does not exist' hint, got %q", out)
	}
}
