package loginero

import (
	"net/http"
	"sync"
	"time"
)

func CurrentSession(r *http.Request) (*Session, error) {
	return defaultInstance.CurrentSession(r)
}

func (loginero *Loginero) CurrentSession(r *http.Request) (*Session, error) {
	loginero.contextMutex.RLock()
	defer loginero.contextMutex.RUnlock()
	ctx := loginero.context[r]
	return ctx.sess, ctx.err
}

func (loginero *Loginero) wrapContext(h http.HandlerFunc, ctx *Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loginero.contextMutex.Lock()
		loginero.context[r] = ctx
		loginero.contextMutex.Unlock()

		h(w, r)

		loginero.contextMutex.Lock()
		delete(loginero.context, r)
		loginero.contextMutex.Unlock()

	}
}

type Session struct {
	ID      string //session id with type (bid:xxxx, sid:xxxx, tid:xxxx)
	UID     string //user id
	Created time.Time
	Anon    bool
}

type SessionStore interface {
	Get(k string) ([]*Session, error)
	Set(k string, sess []*Session) error
	Delete(k string) error
}

type RamSessionStore struct {
	KVStore *RamStore
}

func NewRamSessionStore() SessionStore {
	return &RamSessionStore{
		KVStore: NewRamStore(),
	}
}

func (ss *RamSessionStore) Get(k string) ([]*Session, error) {
	sess, err := ss.KVStore.Get(k)
	if sess == nil {
		return nil, err
	} else {
		return sess.([]*Session), err
	}
}

func (ss *RamSessionStore) Set(k string, sess []*Session) error {
	return ss.KVStore.Set(k, sess)
}

func (ss *RamSessionStore) Delete(k string) error {
	return ss.KVStore.Delete(k)
}

type SessionManager interface {
	BindToken(uid string) (token string, err error)
	FetchBound(token string) (*Session, error)
	GetSession(sid string) (*Session, error)
	GetAnonSession(bid string) (*Session, error)
	CreateSession(sid string, uid string) (*Session, error)
	CreateAnonSession(bid string) (*Session, error)
	DeleteSession(sid string) error
	UserGetSessions(uid string) (sessions []*Session, err error)
	UserAppendSession(uid string, sess *Session) error
	UserRemoveSession(uid string, sess *Session) error
}

type StandardSessionManager struct {
	store SessionStore
	mutex sync.Mutex
}

func (sm StandardSessionManager) BindToken(uid string) (token string, err error) {
	token = generateID()
	k := "tid:" + token
	sess := &Session{
		ID:      k,
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	err = sm.store.Set(k, []*Session{sess})
	return token, err
}

func (sm StandardSessionManager) FetchBound(token string) (*Session, error) {
	k := "tid:" + token
	sessions, err := sm.store.Get(k)
	if err != nil {
		return nil, err
	}
	err = sm.store.Delete(k)
	if err != nil {
		return nil, err
	}
	if len(sessions) > 0 {
		return sessions[0], nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetSession(sid string) (*Session, error) {
	k := "sid:" + sid
	sessions, err := sm.store.Get(k)
	if err != nil {
		return nil, err
	}
	if len(sessions) > 0 {
		return sessions[0], nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetAnonSession(bid string) (*Session, error) {
	k := "bid:" + bid
	sessions, err := sm.store.Get(k)
	if err != nil {
		return nil, err
	}
	if len(sessions) > 0 {
		return sessions[0], nil
	}
	return nil, nil
}

func (sm StandardSessionManager) CreateSession(sid string, uid string) (*Session, error) {
	k := "sid:" + sid
	sess := &Session{
		ID:      k,
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	err := sm.store.Set(k, []*Session{sess})
	if err != nil {
		return nil, err
	}
	err = sm.UserAppendSession(uid, sess)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (sm StandardSessionManager) CreateAnonSession(bid string) (*Session, error) {
	k := "bid:" + bid
	uid := bid
	// Anonymous session points to UID being pure bid
	anonSess := &Session{
		ID:      k,
		UID:     uid,
		Created: time.Now(),
		Anon:    true,
	}
	err := sm.store.Set(k, []*Session{anonSess})
	if err != nil {
		return nil, err
	}
	err = sm.UserAppendSession(uid, anonSess)
	if err != nil {
		return nil, err
	}
	return anonSess, nil
}

// Delete non-anonymous sessions (referenced by sid and not bid)
func (sm StandardSessionManager) DeleteSession(sid string) error {
	k := "sid:" + sid

	sessions, err := sm.store.Get(k)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		uid := sess.UID
		err = sm.UserRemoveSession(uid, sess)
		if err != nil {
			return err
		}
	}

	err = sm.store.Delete(k)
	return err
}

func (sm StandardSessionManager) UserGetSessions(uid string) (sesssions []*Session, err error) {
	k := "uid:" + uid
	return sm.store.Get(k)
}

func (sm StandardSessionManager) UserAppendSession(uid string, sess *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	k := "uid:" + uid
	sessions, err := sm.store.Get(k)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		sessions = []*Session{sess}
	} else {
		sessions = append(sessions, sess)
	}
	return sm.store.Set(k, sessions)
}

func (sm StandardSessionManager) UserRemoveSession(uid string, sess *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	k := "uid:" + uid
	sessions, err := sm.store.Get(k)
	if err != nil {
		return err
	}
	var newsessions []*Session
	for _, s := range sessions {
		if s.ID != sess.ID {
			newsessions = append(newsessions, s)
		}
	}
	return sm.store.Set(k, newsessions)
}
