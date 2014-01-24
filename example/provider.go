package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/GehirnInc/GOpenID"
	"github.com/GehirnInc/GOpenID/provider"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ASSOCIATION_LIFETIME = 60 * 60 * 12 // 12 hours

	URI_PREFIX   = "http://yosida95-ubuntu1:6543"
	STORE_PREFIX = "/home/yosida95/src/GOpenID/src/github.com/GehirnInc/GOpenID/example/assocs/"
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
	return filepath.Join(s.prefix, nonce+".nonce")
}

func (s *FileStore) StoreAssociation(assoc *gopenid.Association) {
	f, err := os.Create(
		s.getAssocSavePath(assoc.GetHandle(), assoc.IsStateless()),
	)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	assocType := assoc.GetAssocType()
	f.Write(bytes.Join([][]byte{
		[]byte(assocType.Name()),
		assoc.GetSecret(),
		[]byte(strconv.FormatInt(assoc.GetExpires(), 10)),
	}, []byte{'\n'}))
}

func (s *FileStore) GetAssociation(assocHandle string, isStateless bool) (assoc *gopenid.Association, ok bool) {
	f, err := os.Open(s.getAssocSavePath(assocHandle, isStateless))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		panic(err)
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	parts := bytes.Split(b, []byte{'\n'})
	if len(parts) != 3 {
		panic(errors.New("invalid association"))
	}

	assocType, err := gopenid.GetAssocTypeByName(string(parts[0]))
	if err != nil {
		panic(err)
	}

	expires, err := strconv.ParseInt(string(parts[2]), 10, 64)
	if err != nil {
		panic(err)
	}

	assoc = gopenid.NewAssociation(assocType, assocHandle, parts[1], expires, isStateless)
	ok = true
	return
}

func (s *FileStore) DeleteAssociation(assoc *gopenid.Association) {
	err := os.Remove(s.getAssocSavePath(assoc.GetHandle(), assoc.IsStateless()))
	if err != nil {
		panic(err)
	}
}

func (s *FileStore) IsKnownNonce(nonce string) bool {
	f, err := os.Open(s.getNonceSvePath(nonce))
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}

		panic(err)
	}
	defer f.Close()

	return true
}

func (s *FileStore) StoreNonce(nonce string) {
	f, err := os.Create(s.getNonceSvePath(nonce))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	return
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

	p.respond(w, r, res)
}

func (p *OpenIDProvider) serveProviderXRDS(w http.ResponseWriter, r *http.Request) {
	p.respond(w, r, p.p.GetYadisProviderIdentifier())
}

func (p *OpenIDProvider) serveClaimedXRDS(w http.ResponseWriter, r *http.Request) {
	p.respond(
		w, r,
		p.p.GetYadisClaimedIdentifier(fmt.Sprintf("%s/users/%s",
			URI_PREFIX,
			strings.SplitN(r.URL.Path, "/", 3)[2],
		)),
	)
}

func main() {
	p := OpenIDProvider{
		p: provider.NewProvider(
			fmt.Sprintf("%s/openid", URI_PREFIX),
			&FileStore{
				prefix: STORE_PREFIX,
			},
			ASSOCIATION_LIFETIME,
		),
	}

	http.HandleFunc("/openid", p.handleRequest)
	http.HandleFunc("/xrds", p.serveProviderXRDS)
	http.HandleFunc("/users/", p.serveClaimedXRDS)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XRDS-Location", fmt.Sprintf("%s/xrds", URI_PREFIX))
		w.Write([]byte("OpenID 2.0 Sample Provider"))
	})

	err := http.ListenAndServe(":6543", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
