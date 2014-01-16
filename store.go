package gopenid

type AssociationStore interface {
	StoreAssociation(*Association) error
	GetAssociation(string, bool) (*Association, error)
	DeleteAssociation(*Association) error
}
