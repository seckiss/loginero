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
	ID       string //session id with type (id2sess:xxxx, token2sess:xxxxx)
	UID      string //user id
	Created  time.Time
	Accessed time.Time
	Anon     bool
}

type SessionManager interface {
	BindToken(uid string) (token string, err error)
	FetchBound(token string) (*Session, error)
	GetSession(id string) (*Session, error)
	CreateSession(id string, uid string, anon bool) (*Session, error)
	DeleteSession(id string) error
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
		ID:       token,
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

func (sm StandardSessionManager) GetSession(id string) (*Session, error) {
	k := "id2sess:" + id
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

func (sm StandardSessionManager) CreateSession(id string, uid string, anon bool) (*Session, error) {
	k := "id2sess:" + id
	sess := Session{
		ID:       id,
		UID:      uid,
		Created:  time.Now(),
		Accessed: time.Now(),
		Anon:     anon,
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

func (sm StandardSessionManager) DeleteSession(id string) error {
	k := "id2sess:" + id

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
// use only for list of session ids
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
