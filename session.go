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
	ID       string //session id with type (bid:xxxx, sid:xxxx, tid:xxxx)
	UID      string //user id
	Created  time.Time
	Accessed time.Time
	Anon     bool
}

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
	k := "token2sess:" + token
	sess := Session{
		ID:       k,
		UID:      uid,
		Created:  time.Now(),
		Accessed: time.Now(),
		Anon:     false,
	}
	err = sm.Store.Put(k, []Session{sess})
	return token, err
}

func (sm StandardSessionManager) FetchBound(token string) (*Session, error) {
	k := "token2sess:" + token
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
		//update Accessed time
		sess.Accessed = time.Now()
		err := sm.Store.Put(k, []Session{sess})
		if err != nil {
			return nil, err
		}
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetSession(sid string) (*Session, error) {
	k := "sid2sess:" + sid
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
		//update Accessed time
		sess.Accessed = time.Now()
		err := sm.Store.Put(k, []Session{sess})
		if err != nil {
			return nil, err
		}
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) GetAnonSession(bid string) (*Session, error) {
	k := "bid2sess:" + bid
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
		//update Accessed time
		sess.Accessed = time.Now()
		err := sm.Store.Put(k, []Session{sess})
		if err != nil {
			return nil, err
		}
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) CreateSession(sid string, uid string) (*Session, error) {
	k := "sid2sess:" + sid
	sess := Session{
		ID:       k,
		UID:      uid,
		Created:  time.Now(),
		Accessed: time.Now(),
		Anon:     false,
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
	k := "bid2sess:" + bid
	uid := bid
	// Anonymous session points to UID being pure bid
	anonSess := Session{
		ID:       k,
		UID:      uid,
		Created:  time.Now(),
		Accessed: time.Now(),
		Anon:     true,
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
	k := "sid2sess:" + sid

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

// return list of sessions linked to the user
// some may be expired, some may already be deleted from the Store
// also the sessions stored here have no updated Accessed field
// use only for list of sids
func (sm StandardSessionManager) UserGetSessions(uid string) (sessions []Session, err error) {
	k := "uid2sess:" + uid
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
	k := "uid2sess:" + uid
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

	k := "uid2sess:" + uid
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
