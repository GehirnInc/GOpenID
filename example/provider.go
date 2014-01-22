package main

import (
	"github.com/GehirnInc/GOpenID"
	"github.com/GehirnInc/GOpenID/provider"
	"log"
	"net/http"
)

const (
	ASSOCIATION_LIFETIME = 60 * 60 * 12 // 12 hours
)

type FileStore struct {
}

func (s *FileStore) StoreAssociation(assoc *gopenid.Association) error {
	return nil
}

func (s *FileStore) GetAssociation(assocHandle string, isStateless bool) (*gopenid.Association, error) {
	return nil, nil
}

func (s *FileStore) DeleteAssociation(assoc *gopenid.Association) error {
	return nil
}

func (s *FileStore) IsKnownNonce(nonce string) (bool, error) {
	return false, nil
}

func (s *FileStore) StoreNonce(nonce string) error {
	return nil
}

func main() {
	store := &FileStore{}
	p := provider.NewProvider("http://localhost:6543/", store, ASSOCIATION_LIFETIME)

	http.HandleFunc("/openid", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		msg, err := gopenid.MessageFromQuery(r.Form)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		session, err := p.EstablishSession(msg)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		res, err := session.GetResponse()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		if res.NeedsRedirect() {
			status := http.StatusFound
			if res.IsPermanently() {
				status = http.StatusMovedPermanently
			}
			http.Redirect(w, r, res.GetRedirectTo(), status)
		} else {
			w.Header().Set("Content-Type", res.GetContentType())
			w.Write(res.GetBody())
		}
	})

	err := http.ListenAndServe(":6543", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
