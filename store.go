package gopenid

type Store interface {
	StoreAssociation(*Association) error
	GetAssociation(string, bool) (*Association, error)
	DeleteAssociation(*Association) error
}
