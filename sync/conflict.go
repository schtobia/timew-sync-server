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
	"fmt"
	"sort"

	"github.com/timewarrior-synchronize/timew-sync-server/data"
	"github.com/timewarrior-synchronize/timew-sync-server/storage"
)

// SolveConflict merges overlapping intervals of given user.
// It then updates userID's state in store accordingly.
// SolveConflict returns true iff a conflict was detected.
func SolveConflict(userID int64, store storage.Storage) (bool, error) {
	conflictDetected := false
	intervals, err := store.GetIntervals(storage.UserID(userID))

	var removed []data.Interval

	var added []data.Interval

	if err != nil {
		return false, fmt.Errorf("getting intervals for user %d: %w", userID, err)
	}

	// Sort intervals by ascending start time (in place)
	sort.SliceStable(intervals, func(i, j int) bool {
		return intervals[i].Start.Before(intervals[j].Start)
	})

	if len(intervals) == 0 {
		return false, nil
	}

	openInterval := intervals[0]

	intervals = intervals[1:] // treat as interval queue sorted by start time

	var addedThisIteration []data.Interval

	// loop invariant:
	// openInterval.Start <= intervals[i].Start for all 0 <= i < len(intervals)
	// and intervals[i].Start <= intervals[i+1].Start for all 0 <= i < len(intervals) - 1
	// in short: append([]data.Interval{openInterval}, intervals) is always sorted by start time
	for len(intervals) > 0 {
		// pop first interval in queue
		interval := intervals[0]
		intervals = intervals[1:]

		addedThisIteration = []data.Interval{}

		if interval.Start.Equal(openInterval.End) || interval.Start.After(openInterval.End) {
			// standard case - no conflict
			openInterval = interval
		} else {
			conflictDetected = true

			removed = append(removed, openInterval, interval)

			endInterval, middleInterval, startInterval := resolveConflict(openInterval, interval)

			if endInterval != nil {
				addedThisIteration = append(addedThisIteration, *endInterval)
			}

			addedThisIteration = append(addedThisIteration, *middleInterval)
			if startInterval != nil {
				addedThisIteration = append(addedThisIteration, *startInterval)
			}

			// getting ready for next iteration
			openInterval = addedThisIteration[len(addedThisIteration)-1]

			added = append(added, addedThisIteration...)

			// reinsert newly created intervals
			intervals = append(intervals, addedThisIteration[:len(addedThisIteration)-1]...)
			sort.SliceStable(intervals, func(i, j int) bool {
				return intervals[i].Start.Before(intervals[j].Start)
			})
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return conflictDetected, nil
	}

	netAdd, netDel := computeNetDiff(added, removed)

	if err := store.ModifyIntervals(storage.UserID(userID), netAdd, netDel); err != nil {
		return conflictDetected, fmt.Errorf("modifying intervals for user %d: %w", userID, err)
	}

	return conflictDetected, nil
}

func computeNetDiff(added, removed []data.Interval) ([]data.Interval, []data.Interval) {
	addedKeys := storage.ConvertToKeys(added)
	removedKeys := storage.ConvertToKeys(removed)

	addedSet := make(map[storage.IntervalKey]int, len(addedKeys))
	for _, key := range addedKeys {
		addedSet[key]++
	}

	removedSet := make(map[storage.IntervalKey]int, len(removedKeys))
	for _, key := range removedKeys {
		removedSet[key]++
	}

	for key, rc := range removedSet {
		if ac, ok := addedSet[key]; ok {
			common := min(ac, rc)
			addedSet[key] -= common

			if addedSet[key] == 0 {
				delete(addedSet, key)
			}

			removedSet[key] -= common

			if removedSet[key] == 0 {
				delete(removedSet, key)
			}
		}
	}

	netAdd := filterBySet(added, addedKeys, addedSet)
	netDel := filterBySet(removed, removedKeys, removedSet)

	return netAdd, netDel
}

func filterBySet(
	intervals []data.Interval,
	keys []storage.IntervalKey,
	set map[storage.IntervalKey]int,
) []data.Interval {
	var result []data.Interval
	for i, key := range keys {
		if set[key] > 0 {
			result = append(result, intervals[i])
			set[key]--
		}
	}

	return result
}

// resolveConflict resolves a conflict between two overlapping intervals.
// It returns up to three new intervals: an optional "end" interval, a "middle" interval,
// and an optional "start" interval.
func resolveConflict(openInterval, interval data.Interval) (*data.Interval, *data.Interval, *data.Interval) {
	var endInterval, middleInterval, startInterval *data.Interval

	// end section (if exists)
	if !openInterval.End.Equal(interval.End) {
		var ei data.Interval
		if openInterval.End.After(interval.End) {
			ei = data.Interval{
				Start:      interval.End,
				End:        openInterval.End,
				Tags:       openInterval.Tags,
				Annotation: openInterval.Annotation,
			}
		} else {
			ei = data.Interval{
				Start:      openInterval.End,
				End:        interval.End,
				Tags:       interval.Tags,
				Annotation: interval.Annotation,
			}
		}

		endInterval = &ei
	}

	// middle section
	tags, annotation := UniteTagsAndAnnotation(openInterval, interval)
	if openInterval.End.After(interval.End) {
		middleInterval = &data.Interval{
			Start:      interval.Start,
			End:        interval.End,
			Tags:       tags,
			Annotation: annotation,
		}
	} else {
		middleInterval = &data.Interval{
			Start:      interval.Start,
			End:        openInterval.End,
			Tags:       tags,
			Annotation: annotation,
		}
	}

	// start section (if exists)
	if !openInterval.Start.Equal(interval.Start) {
		startInterval = &data.Interval{
			Start:      openInterval.Start,
			End:        interval.Start,
			Tags:       openInterval.Tags,
			Annotation: openInterval.Annotation,
		}
	}

	return endInterval, middleInterval, startInterval
}

// UniteTagsAndAnnotation computes the new tags and annotation for overlapping intervals and returns tags, annotation.
// Case 1: Iff only one interval has an Annotation, we use this annotation. Case 2: Iff no interval has an annotation,
// we use "" as annotation. Case 3: Iff both intervals have different annotation, we use "" as annotation, and add both
// annotation to tags. Case 4: Iff both intervals have the same annotation, we just use that annotation
// As tags we return the alphabetically sorted union of both intervals' tags (and both annotations in Case 3)
// without duplicates.
func UniteTagsAndAnnotation(a, b data.Interval) ([]string, string) {
	tags := make([]string, len(a.Tags), len(a.Tags)+len(b.Tags))
	tmp := make([]string, len(b.Tags))
	copy(tags, a.Tags)
	copy(tmp, b.Tags)

	annotation := ""

	tags = append(tags, tmp...)

	switch {
	case a.Annotation != "" && b.Annotation != "" && a.Annotation != b.Annotation:
		tags = append(tags, a.Annotation, b.Annotation)
	case a.Annotation == "":
		annotation = b.Annotation
	default:
		annotation = a.Annotation
	}

	sort.Strings(tags)

	i := 1
	for i < len(tags) {
		if tags[i] == tags[i-1] {
			tags = append(tags[:i], tags[i+1:]...)
		} else {
			i++
		}
	}

	return tags, annotation
}
