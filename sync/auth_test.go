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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// setupKeySet creates a fresh RSA key pair and returns a key set
// containing the public key together with the private signing key.
//
//nolint:ireturn // returning the jwk.Set interface is idiomatic for the JWX library
func setupKeySet(t *testing.T) (jwk.Set, jwk.Key) {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("importing private key: %v", err)
	}

	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("deriving public key: %v", err)
	}

	keySet := jwk.NewSet()
	if err := keySet.AddKey(pub); err != nil {
		t.Fatalf("adding public key to key set: %v", err)
	}

	return keySet, priv
}

// bearerRequest signs a token for the given user with the given key
// and returns an HTTP request carrying it as Bearer token.
func bearerRequest(t *testing.T, signingKey jwk.Key, userID int64, setExpiration func(jwt.Token)) *http.Request {
	t.Helper()

	token := jwt.New()
	if err := token.Set("userID", userID); err != nil {
		t.Fatalf("token.Set userID: %v", err)
	}

	if setExpiration != nil {
		setExpiration(token)
	}

	payload, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+string(payload))

	return req
}

func TestAuthenticateWithKeySet_positive(t *testing.T) {
	raw1, err1 := rsa.GenerateKey(rand.Reader, 2048)
	raw2, err2 := rsa.GenerateKey(rand.Reader, 2048)
	key1, err3 := jwk.Import(raw1)
	key2, err4 := jwk.Import(raw2)
	pub1, err5 := jwk.PublicKeyOf(key1)
	pub2, err6 := jwk.PublicKeyOf(key2)
	keySet := jwk.NewSet()
	err7 := keySet.AddKey(pub1)
	err8 := keySet.AddKey(pub2)

	token := jwt.New()
	if err := token.Set("userID", 42); err != nil {
		t.Fatalf("token.Set userID: %v", err)
	}

	if err := token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("token.Set expiration: %v", err)
	}

	payload, err9 := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key2))
	bearer := "Bearer " + string(payload)
	req, err10 := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	req.Header.Add("Authorization", bearer)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil ||
		err8 != nil || err9 != nil || err10 != nil {
		t.Errorf("Failed to generate key set in preparation for testing")
	}

	b := AuthenticateWithKeySet(req, 42, keySet)
	if !b {
		t.Errorf("Failed to authenticate")
	}
}

func TestAuthenticateWithKeySet_negative(t *testing.T) {
	raw1, err1 := rsa.GenerateKey(rand.Reader, 2048)
	raw2, err2 := rsa.GenerateKey(rand.Reader, 2048)
	key1, err3 := jwk.Import(raw1)
	key2, err4 := jwk.Import(raw2)
	pub1, err5 := jwk.PublicKeyOf(key1)
	keySet := jwk.NewSet()
	err7 := keySet.AddKey(pub1)

	token := jwt.New()
	if err := token.Set("userID", 42); err != nil {
		t.Fatalf("token.Set userID: %v", err)
	}

	if err := token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("token.Set expiration: %v", err)
	}

	payload, err9 := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key2))
	bearer := "Bearer " + string(payload)
	req, err10 := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	req.Header.Add("Authorization", bearer)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err7 != nil ||
		err9 != nil || err10 != nil {
		t.Errorf("Failed to generate key set in preparation for testing")
	}

	b := AuthenticateWithKeySet(req, 42, keySet)
	if b {
		t.Errorf("Authenticated falsely")
	}
}

func TestAuthenticateWithKeySet_expired(t *testing.T) {
	raw1, err1 := rsa.GenerateKey(rand.Reader, 2048)
	raw2, err2 := rsa.GenerateKey(rand.Reader, 2048)
	key1, err3 := jwk.Import(raw1)
	key2, err4 := jwk.Import(raw2)
	pub1, err5 := jwk.PublicKeyOf(key1)
	pub2, err6 := jwk.PublicKeyOf(key2)
	keySet := jwk.NewSet()
	err7 := keySet.AddKey(pub1)
	err8 := keySet.AddKey(pub2)

	token := jwt.New()
	if err := token.Set("userID", 42); err != nil {
		t.Fatalf("token.Set userID: %v", err)
	}

	if err := token.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("token.Set expiration: %v", err)
	}

	payload, err9 := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key2))
	bearer := "Bearer " + string(payload)
	req, err10 := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	req.Header.Add("Authorization", bearer)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil ||
		err8 != nil || err9 != nil || err10 != nil {
		t.Errorf("Failed to generate key set in preparation for testing")
	}

	b := AuthenticateWithKeySet(req, 42, keySet)
	if b {
		t.Errorf("Authenticated with expired jwt")
	}
}

func TestAuthenticateWithKeySet_IDMismatch(t *testing.T) {
	raw1, err1 := rsa.GenerateKey(rand.Reader, 2048)
	raw2, err2 := rsa.GenerateKey(rand.Reader, 2048)
	key1, err3 := jwk.Import(raw1)
	key2, err4 := jwk.Import(raw2)
	pub1, err5 := jwk.PublicKeyOf(key1)
	pub2, err6 := jwk.PublicKeyOf(key2)
	keySet := jwk.NewSet()
	err7 := keySet.AddKey(pub1)
	err8 := keySet.AddKey(pub2)

	token := jwt.New()
	if err := token.Set("userID", 42); err != nil {
		t.Fatalf("token.Set userID: %v", err)
	}

	if err := token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("token.Set expiration: %v", err)
	}

	payload, err9 := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key2))
	bearer := "Bearer " + string(payload)
	req, err10 := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	req.Header.Add("Authorization", bearer)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil ||
		err8 != nil || err9 != nil || err10 != nil {
		t.Errorf("Failed to generate key set in preparation for testing")
	}

	b := AuthenticateWithKeySet(req, 0, keySet)
	if b {
		t.Errorf("Authenticated with mismatching userIDs")
	}
}

func TestAuthenticateWithKeySet_NoExpiration(t *testing.T) {
	keySet, priv := setupKeySet(t)

	req := bearerRequest(t, priv, 42, nil)

	if AuthenticateWithKeySet(req, 42, keySet) {
		t.Errorf("Authenticated with jwt missing the required exp claim")
	}
}

func TestAuthenticateWithKeySet_SkewExceeded(t *testing.T) {
	keySet, priv := setupKeySet(t)

	req := bearerRequest(t, priv, 42, func(token jwt.Token) {
		if err := token.Set(jwt.ExpirationKey, time.Now().Add(-2*acceptableSkew)); err != nil {
			t.Fatalf("token.Set expiration: %v", err)
		}
	})

	if AuthenticateWithKeySet(req, 42, keySet) {
		t.Errorf("Authenticated with jwt expired beyond the acceptable skew")
	}
}

func TestAuthenticateWithKeySet_WithinSkew(t *testing.T) {
	keySet, priv := setupKeySet(t)

	req := bearerRequest(t, priv, 42, func(token jwt.Token) {
		if err := token.Set(jwt.ExpirationKey, time.Now().Add(-acceptableSkew/2)); err != nil {
			t.Fatalf("token.Set expiration: %v", err)
		}
	})

	if !AuthenticateWithKeySet(req, 42, keySet) {
		t.Errorf("Failed to authenticate with jwt expired within the acceptable skew")
	}
}

func TestFilterKeySet(t *testing.T) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("importing private key: %v", err)
	}

	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("deriving public key: %v", err)
	}

	oct, err := jwk.Import([]byte("symmetric-secret"))
	if err != nil {
		t.Fatalf("importing symmetric key: %v", err)
	}

	keySet := jwk.NewSet()
	if err := keySet.AddKey(oct); err != nil {
		t.Fatalf("adding symmetric key: %v", err)
	}

	if err := keySet.AddKey(priv); err != nil {
		t.Fatalf("adding private key: %v", err)
	}

	if err := keySet.AddKey(pub); err != nil {
		t.Fatalf("adding public key: %v", err)
	}

	filtered := filterKeySet(keySet)
	if filtered.Len() != 1 {
		t.Fatalf("expected 1 key after filtering, got %d", filtered.Len())
	}

	var want, got rsa.PublicKey
	if err := jwk.Export(pub, &want); err != nil {
		t.Fatalf("exporting expected public key: %v", err)
	}

	key, _ := filtered.Key(0)
	if err := jwk.Export(key, &got); err != nil {
		t.Fatalf("exporting filtered key: %v", err)
	}

	if want.N.Cmp(got.N) != 0 || want.E != got.E {
		t.Errorf("filtered key does not match the RSA public key")
	}
}

func TestGetKeySet_FiltersNonPublicKeys(t *testing.T) {
	tmpDir := t.TempDir()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(raw)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&raw.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	cfg := &ServerConfig{KeyLocation: tmpDir}

	if err := os.WriteFile(filepath.Join(tmpDir, "0_keys"), privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keySet, err := cfg.GetKeySet(0)
	if err != nil {
		t.Fatalf("GetKeySet: %v", err)
	}

	if keySet.Len() != 0 {
		t.Errorf("expected private key to be filtered, got %d keys", keySet.Len())
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "1_keys"), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keySet, err = cfg.GetKeySet(1)
	if err != nil {
		t.Fatalf("GetKeySet: %v", err)
	}

	if keySet.Len() != 1 {
		t.Errorf("expected public key to be kept, got %d keys", keySet.Len())
	}
}
