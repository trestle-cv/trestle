// Package replerr defines the deterministic per-operation caller conflicts a
// replicated Trestle mutation can produce. These are distinct from replica
// corruption: an operation carrying a stale precondition or a duplicate
// collection name is rejected for its caller while the replica stays healthy.
package replerr

import "errors"

var (
	// ErrCollectionConflict reports a deterministic per-operation caller
	// conflict: a collection name committed under two different IDs (a racing
	// duplicate create). The operation is rejected for its caller; it is not
	// replica corruption.
	ErrCollectionConflict = errors.New("collection conflict")
	// ErrStalePrecondition reports a deterministic per-operation caller
	// conflict: a record create/update/delete carrying a stale version. The
	// operation is rejected for its caller; it is not replica corruption.
	ErrStalePrecondition = errors.New("stale record precondition")
)

// IsSemanticConflict reports whether e is a deterministic per-operation caller
// conflict that must be rejected for the caller without fencing the replica.
func IsSemanticConflict(e error) bool {
	return errors.Is(e, ErrCollectionConflict) || errors.Is(e, ErrStalePrecondition)
}