package gopenid

// Store is a interface of data store.
//
// GopenID users must implement this interface to use.
type Store interface {
	StoreAssociation(*Association)
	GetAssociation(string, bool) (*Association, bool)
	DeleteAssociation(*Association)
	IsKnownNonce(string) bool
	StoreNonce(string)
}
