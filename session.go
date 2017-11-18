package loginero

import (
	"net/http"
	"sync"
	"time"
)

var context = make(map[*http.Request]struct {
	sess *Session
	err  error
})
var contextMutex sync.RWMutex
var dsm SessionManager

func BindToken(uid string) (token string, err error) {
	return dsm.BindToken(uid)
}

func CurrentSession(r *http.Request) (*Session, error) {
	contextMutex.RLock()
	defer contextMutex.RUnlock()
	ctx := context[r]
	return ctx.sess, ctx.err
}

func wrapContext(h http.HandlerFunc, sess *Session, err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		contextMutex.Lock()
		context[r] = struct {
			sess *Session
			err  error
		}{sess, err}
		contextMutex.Unlock()

		h(w, r)

		contextMutex.Lock()
		delete(context, r)
		contextMutex.Unlock()

	}
}

type Session struct {
	UID     string
	Created time.Time
	Anon    bool
}

type SessionStore interface {
	Get(k string) (*Session, error)
	Set(k string, s *Session) error
	Delete(k string) error
}

type SessionManager interface {
	BindToken(uid string) (token string, err error)
	FetchBound(token string, bid string) (*Session, error)
	GetSession(sid string) (*Session, error)
	GetAnonSession(bid string) (*Session, error)
	CreateSession(sid string, uid string) error
	CreateAnonSession(bid string) (*Session, error)
	DeleteSessionUser(sid string) error
}

type StandardSessionManager struct {
	store SessionStore
}

func (sm StandardSessionManager) BindToken(uid string, bid string) (token string, err error) {
	token = generateID()
	k := "tid:" + token
	sess := Session{
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	err = sm.store.Set(k, &sess)
	return token, err
}

func (sm StandardSessionManager) FetchBound(token string, bid string) (*Session, error) {
	k := "tid:" + token
	sess, err := sm.store.Get(k)
	if err != nil {
		return nil, err
	}
	err = sm.store.Delete(k)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (sm StandardSessionManager) GetSession(sid string) (*Session, error) {
	k := "sid:" + sid
	sess, err := sm.store.Get(k)
	if err != nil {
		return nil, err
	}
	if sess != nil {
		return sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetAnonSession(bid string) (*Session, error) {
	k := "bid:" + bid
	sess, err := sm.store.Get(k)
	if err != nil {
		return nil, err
	}
	if sess != nil {
		return sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) CreateSession(sid string, uid string) error {
	k := "sid:" + sid
	sess := Session{
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	return sm.store.Set(k, &sess)
}

func (sm StandardSessionManager) CreateAnonSession(bid string) (*Session, error) {
	k := "bid:" + bid
	anonSess := Session{
		UID:     k,
		Created: time.Now(),
		Anon:    true,
	}
	err := sm.store.Set(k, &anonSess)
	if err != nil {
		return nil, err
	}
	return &anonSess, nil
}

func (sm StandardSessionManager) DeleteSession(sid string) error {
	k := "sid:" + sid
	err := sm.store.Delete(k)
	return err
}
