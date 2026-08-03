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
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/timewarrior-synchronize/timew-sync-server/data"
)

const (
	acceptableSkew      = time.Duration(10e10)
	expectedFilenameLen = 2
	keyFilePermissions  = 0o644
)

// Authenticate returns true iff the JWT specified in the HTTP requests' Bearer token was signed by the correct user.
// If any step of the authentication process fails or there is no matching public key, Authenticate returns false.
func Authenticate(r *http.Request, body data.SyncRequest, keyLocation string) bool {
	keySet, err := GetKeySet(body.UserID, keyLocation)
	if err != nil {
		log.Printf("Error during Authentication. Unable to obtain keys for user %v", body.UserID)

		return false
	}

	return AuthenticateWithKeySet(r, body.UserID, keySet)
}

// AuthenticateWithKeySet returns true iff the JWT in the Bearer token can be validated in verified with a key in the
// given key set.
func AuthenticateWithKeySet(r *http.Request, userID int64, keySet jwk.Set) bool {
	for i := range keySet.Len() {
		key, ok := keySet.Key(i)
		if !ok {
			continue
		}

		token, err := jwt.ParseHeader(r.Header, "Authorization", jwt.WithValidate(true),
			jwt.WithKey(jwa.RS256(), key), jwt.WithAcceptableSkew(acceptableSkew))
		if err != nil {
			continue
		}

		var presumedUserID float64
		if err := token.Get("userID", &presumedUserID); err != nil {
			continue
		}

		if int64(presumedUserID) != userID {
			continue
		}

		return true
	}

	return false
}

// GetKeySet returns the key set of user with a given userID. Returns an error if the keys file of that user was not
// found or could not be parsed.
//
//nolint:ireturn // returning the jwk.Set interface is idiomatic for the JWX library
func GetKeySet(userID int64, keyLocation string) (jwk.Set, error) {
	filename := fmt.Sprintf("%d_keys", userID)
	path := filepath.Join(keyLocation, filename)

	keySet, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		log.Printf("Error parsing key set of user %d: %v", userID, err)

		return nil, err
	}

	return keySet, nil
}
