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

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/timewarrior-synchronize/timew-sync-server/storage"
	"github.com/timewarrior-synchronize/timew-sync-server/sync"
)

const (
	version = "1.2.0"

	minArgs           = 2
	defaultPort       = 8080
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

func main() {
	os.Exit(realMain(os.Args))
}

// realMain contains the actual CLI dispatch logic so it can be tested
// without running os.Exit directly in the test process. It returns the
// exit code that main should pass to os.Exit.
func realMain(args []string) int {
	if len(args) < minArgs {
		_, _ = fmt.Fprintf(os.Stderr, "Use commands start, add-user or add-key\n")

		return 1
	}

	switch args[1] {
	case "start":
		runStart(args[2:])

		return 0
	case "add-user":
		return runAddUser(args[2:])
	case "add-key":
		return runAddKey(args[2:])
	default:
		var versionFlag bool

		cmd := flag.NewFlagSet("version", flag.ContinueOnError)
		cmd.SetOutput(os.Stderr)
		cmd.BoolVar(&versionFlag, "version", false, "Print version information")

		if err := cmd.Parse(args[1:]); err != nil {
			return 1
		}

		if versionFlag {
			_, _ = fmt.Fprintf(os.Stderr, "timewarrior sync server version %v\n", version)

			return 0
		}

		_, _ = fmt.Fprintln(os.Stderr, "Use commands start, add-user or add-key")

		return 1
	}
}

// runStart starts the sync server.
func runStart(args []string) {
	var (
		configFilePath   string
		portNumber       int
		keyDirectoryPath string
		dbPath           string
		noAuth           bool
	)

	cmd := flag.NewFlagSet("start", flag.ExitOnError)
	cmd.StringVar(&configFilePath, "config-file", "", "[RESERVED, not used] Path to the configuration file")
	cmd.StringVar(&dbPath, "sqlite-db", "db.sqlite", "Path to the SQLite database")
	cmd.IntVar(&portNumber, "port", defaultPort, "Port on which the server will listen for connections")
	cmd.StringVar(&keyDirectoryPath, "keys-location", "authorized_keys", "Path to the users' public keys")
	cmd.BoolVar(&noAuth, "no-auth", false, "Run server without client authentication")
	_ = cmd.Parse(args)
	_ = configFilePath

	db, err := storage.OpenSQLite(dbPath)
	if err != nil {
		log.Fatalf("Error while opening SQLite database: %v", err)
	}

	defer db.Close()

	sqlStorage := &storage.SQL{DB: db} //nolint:exhaustruct // LockerRoom is initialized in Initialize()
	if err := sqlStorage.Initialize(); err != nil {
		log.Fatalf("Error while initializing database: %v", err) //nolint:gocritic
	}

	cfg := &sync.ServerConfig{
		Store:       sqlStorage,
		KeyLocation: keyDirectoryPath,
		KeyCache:    sync.NewKeyCache(),
		NoAuth:      noAuth,
	}

	syncHandler := func(w http.ResponseWriter, req *http.Request) {
		sync.HandleSyncRequest(cfg, w, req)
	}
	healthHandler := func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "OK")
	}

	http.HandleFunc("/api/sync", syncHandler)
	http.HandleFunc("/api/health", healthHandler)

	log.Printf("Listening on Port %v", portNumber)
	srv := &http.Server{ //nolint:exhaustruct // optional fields are intentionally omitted
		Addr:              fmt.Sprintf(":%v", portNumber),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	log.Fatal(srv.ListenAndServe())
}

// runAddUser adds a new user. Returns the exit code.
func runAddUser(args []string) int {
	var (
		sourcePath       string
		keyDirectoryPath string
	)

	cmd := flag.NewFlagSet("add-user", flag.ExitOnError)
	cmd.StringVar(&sourcePath, "path", "", "Supply the path to a PEM RSA key")
	cmd.StringVar(&keyDirectoryPath, "keys-location", "authorized_keys", "Path to the users' public keys")
	_ = cmd.Parse(args)

	id := sync.GetFreeUserID(keyDirectoryPath)
	if sourcePath == "" {
		sync.AddKey(keyDirectoryPath, id, "")
	} else {
		key := sync.ReadKey(sourcePath)
		sync.AddKey(keyDirectoryPath, id, key)
	}

	_, _ = fmt.Fprintf(os.Stderr, "Successfully added new user %v", id)

	return 0
}

// runAddKey adds a new key to an existing user. Returns the exit code
// (non-zero if validation fails).
func runAddKey(args []string) int {
	var (
		sourcePath       string
		userID           int64
		keyDirectoryPath string
	)

	cmd := flag.NewFlagSet("add-key", flag.ExitOnError)
	cmd.StringVar(&sourcePath, "path", "", "Supply the path to a PEM RSA key")
	cmd.Int64Var(&userID, "id", -1, "Supply user id")
	cmd.StringVar(&keyDirectoryPath, "keys-location", "authorized_keys", "Path to the users' public keys")
	_ = cmd.Parse(args)

	if sourcePath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "Provide a key file with --path [path-to-key-file]")

		return 1
	}

	if userID < 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Provide a non-negative user id with --id [user id]")

		return 1
	}

	used := sync.GetUsedUserIDs(keyDirectoryPath)
	if !used[userID] {
		_, _ = fmt.Fprintf(os.Stderr, "User %v does not exist\n", userID)

		return 1
	}

	key := sync.ReadKey(sourcePath)
	sync.AddKey(keyDirectoryPath, userID, key)
	_, _ = fmt.Fprintf(os.Stderr, "Successfully added new key to user %v", userID)

	return 0
}
