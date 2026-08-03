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

package sync

import (
	"errors"
	"fmt"

	"github.com/timewarrior-synchronize/timew-sync-server/data"
	"github.com/timewarrior-synchronize/timew-sync-server/storage"
)

var (
	errBackupFailed       = errors.New("could not retrieve stored intervals for backup, stored state did not change")
	errRetrieveFailed     = errors.New("failed to retrieve intervals from storage, stored state did not change")
	errRetrieveRestoreBad = errors.New("failed to retrieve intervals from storage, also could not restore server state")
)

// Sync updates the stored state in passed storage.Storage for the user issuing the sync request. If something fails it
// tries to restore the state
// prior to the syncRequest. This is not always possible though. The error message denotes whether restoring state was
// successful.
// Later atomicity should be guaranteed by storage.
// Iff no errors occur Sync returns the synced interval data of the user issuing the sync request.
func Sync(syncRequest data.SyncRequest, store storage.Storage) ([]data.Interval, bool, error) {
	// acquire lock and release it after syncing
	store.Lock(storage.UserID(syncRequest.UserID))
	defer store.Unlock(storage.UserID(syncRequest.UserID))

	// First, create a backup
	backup, err := store.GetIntervals(storage.UserID(syncRequest.UserID))
	if err != nil {
		return nil, false, errBackupFailed
	}

	// Apply diff
	diffErr := store.ModifyIntervals(storage.UserID(syncRequest.UserID), syncRequest.Added, syncRequest.Removed)
	if diffErr != nil {
		restoreError := store.SetIntervals(storage.UserID(syncRequest.UserID), backup) // try to restore backup
		if restoreError != nil {
			return nil, false, fmt.Errorf("fatal error: failed to apply diff %w. "+
				"Also could not restore server state", diffErr)
		}

		return nil, false, fmt.Errorf("fatal error: failed to apply diff %w. "+
			"Stored state unchanged", diffErr)
	}

	conflict, solveErr := SolveConflict(syncRequest.UserID, store)
	if solveErr != nil {
		restoreError := store.SetIntervals(storage.UserID(syncRequest.UserID), backup) // try to restore backup
		if restoreError != nil {
			return nil, conflict, fmt.Errorf("fatal error: failed to solve conflicts %w. "+
				"Also could not restore server state", solveErr)
		}

		return nil, conflict, fmt.Errorf("fatal error: failed to solve conflicts %w. "+
			"Stored state unchanged", solveErr)
	}

	result, err2 := store.GetIntervals(storage.UserID(syncRequest.UserID))
	if err2 != nil {
		restoreError := store.SetIntervals(storage.UserID(syncRequest.UserID), backup) // trying to restore backup
		if restoreError != nil {
			return nil, conflict, errRetrieveRestoreBad
		}

		return nil, conflict, errRetrieveFailed
	}

	return result, conflict, nil
}
