package gopenid

type Store interface {
	StoreAssociation(*Association) error
	GetAssociation(string, bool) (*Association, error)
	DeleteAssociation(*Association) error
	IsKnownNonce(nonce string) (bool, error)
	StoreNonce(nonce string) error
}
