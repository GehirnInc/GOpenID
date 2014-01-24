package main

import (
	"bytes"
	"errors"
	"github.com/GehirnInc/GOpenID"
	"github.com/GehirnInc/GOpenID/provider"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

const (
	ASSOCIATION_LIFETIME = 60 * 60 * 12 // 12 hours
)

type FileStore struct {
	prefix string
}

func (s *FileStore) getAssocSavePath(handle string, isStateless bool) string {
	ext := ".stateful"
	if isStateless {
		ext = ".stateless"
	}
	return filepath.Join(s.prefix, handle+ext)
}

func (s *FileStore) getNonceSvePath(nonce string) string {
	ext := ".nonce"
	return filepath.Join(s.prefix, nonce+ext)
}

func (s *FileStore) StoreAssociation(assoc *gopenid.Association) error {
	f, err := os.Create(
		s.getAssocSavePath(assoc.GetHandle(), assoc.IsStateless()),
	)
	if err != nil {
		return err
	}
	defer f.Close()

	assocType := assoc.GetAssocType()
	f.Write(bytes.Join([][]byte{
		[]byte(assocType.Name()),
		assoc.GetSecret(),
		[]byte(strconv.FormatInt(assoc.GetExpires(), 10)),
	}, []byte{'\n'}))
	return nil
}

func (s *FileStore) GetAssociation(assocHandle string, isStateless bool) (assoc *gopenid.Association, err error) {
	f, err := os.Open(s.getAssocSavePath(assocHandle, isStateless))
	if err != nil {
		return
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	parts := bytes.Split(b, []byte{'\n'})
	if len(parts) != 3 {
		err = errors.New("invalid association")
		return
	}

	assocType, err := gopenid.GetAssocTypeByName(string(parts[0]))
	if err != nil {
		return
	}

	expires, err := strconv.ParseInt(string(parts[2]), 10, 64)
	if err != nil {
		return
	}

	assoc = gopenid.NewAssociation(assocType, assocHandle, parts[1], expires, isStateless)
	return
}

func (s *FileStore) DeleteAssociation(assoc *gopenid.Association) error {
	return os.Remove(s.getAssocSavePath(assoc.GetHandle(), assoc.IsStateless()))
}

func (s *FileStore) IsKnownNonce(nonce string) (bool, error) {
	f, err := os.Open(s.getNonceSvePath(nonce))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, err
	}
	defer f.Close()
	return true, nil
}

func (s *FileStore) StoreNonce(nonce string) error {
	f, err := os.Create(s.getNonceSvePath(nonce))
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

type OpenIDProvider struct {
	p *provider.Provider
}

func (p *OpenIDProvider) respond(w http.ResponseWriter, r *http.Request, res provider.Response) {
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
}

func (p *OpenIDProvider) handleRequest(w http.ResponseWriter, r *http.Request) {
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

	kv, _ := msg.ToKeyValue(msg.Keys())
	session, err := p.p.EstablishSession(msg)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	switch ret := session.(type) {
	case *provider.CheckIDSession:
		ret.Accept(
			"http://yosida95-ubuntu1:6543/users/yosida95",
			"http://yosida95-ubuntu1:6543/users/yosida95",
		)
	}

	res, err := session.GetResponse()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	switch ret := res.(type) {
	case *provider.OpenIDResponse:
		msg := ret.GetMessage()
		kv, _ := msg.ToKeyValue(msg.Keys())
	}

	p.respond(w, r, res)
}

func (p *OpenIDProvider) serveProviderXRDS(w http.ResponseWriter, r *http.Request) {
	p.respond(w, r, p.p.GetYadisProviderIdentifier())
}

func (p *OpenIDProvider) serveClaimedXRDS(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path)
	p.respond(w, r, p.p.GetYadisClaimedIdentifier(""))
}

func main() {
	store := &FileStore{
		prefix: "/home/yosida95/src/GOpenID/src/github.com/GehirnInc/GOpenID/example/assocs/",
	}
	p := OpenIDProvider{
		p: provider.NewProvider("http://yosida95-ubuntu1:6543/openid", store, ASSOCIATION_LIFETIME),
	}

	http.HandleFunc("/openid", p.handleRequest)
	http.HandleFunc("/xrds", p.serveProviderXRDS)
	http.HandleFunc("/users/", p.serveClaimedXRDS)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XRDS-Location", "http://yosida95-ubuntu1:6543/xrds")

		w.Write([]byte("OpenID 2.0 Sample Provider"))
	})

	err := http.ListenAndServe(":6543", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
