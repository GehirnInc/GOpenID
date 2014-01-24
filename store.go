package gopenid

type Store interface {
	StoreAssociation(*Association)
	GetAssociation(string, bool) (*Association, bool)
	DeleteAssociation(*Association)
	IsKnownNonce(string) bool
	StoreNonce(string)
}
