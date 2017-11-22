package loginero

import (
	"net/http"
	"sync"
	"time"
)

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

/*
func (ss *RamSessionStore) Get(k string) ([]*Session, error) {
	sess, err := ss.KVStore.Get(k)
	if sess == nil {
		return nil, err
	} else {
		return sess.([]*Session), err
	}
}
*/

type SessionManager interface {
	BindToken(uid string) (token string, err error)
	FetchBound(token string) (*Session, error)
	GetSession(sid string) (*Session, error)
	GetAnonSession(bid string) (*Session, error)
	CreateSession(sid string, uid string) (*Session, error)
	CreateAnonSession(bid string) (*Session, error)
	DeleteSession(sid string) error
	UserGetSessions(uid string) (sessions []Session, err error)
	UserAppendSession(uid string, sess *Session) error
	UserRemoveSession(uid string, sess *Session) error
}

type StandardSessionManager struct {
	Store KeyValueStore
	mutex sync.Mutex
}

func (sm StandardSessionManager) BindToken(uid string) (token string, err error) {
	token = generateID()
	k := "tid:" + token
	sess := Session{
		ID:      k,
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	err = sm.Store.Put(k, []Session{sess})
	return token, err
}

func (sm StandardSessionManager) FetchBound(token string) (*Session, error) {
	k := "tid:" + token
	value, err := sm.Store.Get(k)
	if err != nil {
		return nil, err
	}
	err = sm.Store.Delete(k)
	if err != nil {
		return nil, err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	if len(sessions) > 0 {
		var sess = sessions[0]
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetSession(sid string) (*Session, error) {
	k := "sid:" + sid
	value, err := sm.Store.Get(k)
	if err != nil {
		return nil, err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	if len(sessions) > 0 {
		var sess = sessions[0]
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetAnonSession(bid string) (*Session, error) {
	k := "bid:" + bid
	value, err := sm.Store.Get(k)
	if err != nil {
		return nil, err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	if len(sessions) > 0 {
		var sess = sessions[0]
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) CreateSession(sid string, uid string) (*Session, error) {
	k := "sid:" + sid
	sess := Session{
		ID:      k,
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	err := sm.Store.Put(k, []Session{sess})
	if err != nil {
		return nil, err
	}
	err = sm.UserAppendSession(uid, &sess)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (sm StandardSessionManager) CreateAnonSession(bid string) (*Session, error) {
	k := "bid:" + bid
	uid := bid
	// Anonymous session points to UID being pure bid
	anonSess := Session{
		ID:      k,
		UID:     uid,
		Created: time.Now(),
		Anon:    true,
	}
	err := sm.Store.Put(k, []Session{anonSess})
	if err != nil {
		return nil, err
	}
	err = sm.UserAppendSession(uid, &anonSess)
	if err != nil {
		return nil, err
	}
	return &anonSess, nil
}

// Delete non-anonymous sessions (referenced by sid and not bid)
func (sm StandardSessionManager) DeleteSession(sid string) error {
	k := "sid:" + sid

	value, err := sm.Store.Get(k)
	if err != nil {
		return err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	for _, sess := range sessions {
		uid := sess.UID
		err = sm.UserRemoveSession(uid, &sess)
		if err != nil {
			return err
		}
	}

	err = sm.Store.Delete(k)
	return err
}

func (sm StandardSessionManager) UserGetSessions(uid string) (sessions []Session, err error) {
	k := "uid:" + uid
	value, err := sm.Store.Get(k)
	if err != nil {
		return nil, err
	}
	if value != nil {
		sessions = value.([]Session)
	}
	return sessions, nil
}

func (sm StandardSessionManager) UserAppendSession(uid string, sess *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	k := "uid:" + uid
	value, err := sm.Store.Get(k)
	if err != nil {
		return err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	if len(sessions) == 0 {
		sessions = []Session{*sess}
	} else {
		sessions = append(sessions, *sess)
	}
	return sm.Store.Put(k, sessions)
}

func (sm StandardSessionManager) UserRemoveSession(uid string, sess *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	k := "uid:" + uid
	value, err := sm.Store.Get(k)
	if err != nil {
		return err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	var newsessions []Session
	for _, s := range sessions {
		if s.ID != sess.ID {
			newsessions = append(newsessions, s)
		}
	}
	return sm.Store.Put(k, newsessions)
}
