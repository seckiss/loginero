package loginero

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Device represents a browser and not a physical device
// It may be for example WebPush subscription that is stable per (browser, domain)
// Device must implement Hasher interface to calculate unique Hash() of the device

type Hasher interface {
	Hash() string
}

func (lo *Loginero) CurrentSession(r *http.Request) (*Session, error) {
	lo.contextMutex.RLock()
	defer lo.contextMutex.RUnlock()
	ctx := lo.context[r]
	return ctx.sess, ctx.err
}

func (lo *Loginero) wrapContext(h http.HandlerFunc, ctx *Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lo.contextMutex.Lock()
		lo.context[r] = ctx
		lo.contextMutex.Unlock()

		if ctx.err != nil {
			fmt.Printf("loginero error: %v\n", ctx.err)
		}
		h(w, r)

		lo.contextMutex.Lock()
		delete(lo.context, r)
		lo.contextMutex.Unlock()

	}
}

type Session struct {
	ID      string // session id
	UID     string // user id
	Created time.Time
	Anon    bool
}

type SessionManager interface {
	// Core session
	GetSession(id string) (*Session, error)
	AccessSession(id string) error
	CreateSession(id string, uid string, anon bool) (*Session, error)
	DeleteSession(id string) error
	// Token related
	BindToken(uid string) (token string, err error)
	FetchBound(token string) (*Session, error)
	// User related
	UserGetSessions(uid string) (sessions []Session, err error)
	UserAppendSession(uid string, sess *Session) error
	UserRemoveSession(uid string, sess *Session) error
	// Device related
	GetDeviceForSession(id string) (device Hasher, err error)
	SetDeviceForSession(session *Session, device Hasher) error
	DeleteDeviceForSession(sessionid string, device Hasher) error
	CurrentSessionForDevice(device Hasher) (id string, err error)
}

type StandardSessionManager struct {
	Store TypeKeyValueStore
	mutex sync.Mutex
}

func (sm StandardSessionManager) BindToken(uid string) (token string, err error) {
	token = GenerateID()
	sess := Session{
		ID:      token,
		UID:     uid,
		Created: time.Now(),
		Anon:    false,
	}
	err = sm.Store.Put("token2sess", token, []Session{sess})
	return token, err
}

func (sm StandardSessionManager) FetchBound(token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	value, err := sm.Store.Get("token2sess", token)
	if err != nil {
		return nil, err
	}
	err = sm.Store.Delete("token2sess", token)
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

func (sm StandardSessionManager) GetSession(id string) (*Session, error) {
	if id == "" {
		return nil, nil
	}
	value, err := sm.Store.Get("id2sess", id)
	if err != nil {
		return nil, err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	if len(sessions) > 0 {
		var sess = sessions[0]

		//delete session if expired
		expire := map[bool]time.Duration{false: namedSessionExpireTime, true: anonSessionExpireTime}
		lastAccessed, err := sm.SessionLastAccessed(id)
		if err != nil {
			return nil, err
		}
		if lastAccessed != nil && time.Now().Sub(*lastAccessed) > expire[sess.Anon] {
			err := sm.DeleteSession(id)
			if err != nil {
				return nil, err
			}
		}
		return &sess, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) SessionLastAccessed(id string) (*time.Time, error) {
	if id == "" {
		return nil, nil
	}
	value, err := sm.Store.Get("id2accessed", id)
	if err != nil {
		return nil, err
	}
	if value != nil {
		lastAccessed := value.(time.Time)
		return &lastAccessed, nil
	}
	return nil, nil
}

func (sm StandardSessionManager) AccessSession(id string) error {
	if id == "" {
		return nil
	}
	return sm.Store.Put("id2accessed", id, time.Now())
}

func (sm StandardSessionManager) CreateSession(id string, uid string, anon bool) (*Session, error) {
	sess := Session{
		ID:      id,
		UID:     uid,
		Created: time.Now(),
		Anon:    anon,
	}
	err := sm.Store.Put("id2sess", id, []Session{sess})
	if err != nil {
		return nil, err
	}
	err = sm.AccessSession(id)
	if err != nil {
		return nil, err
	}

	// Anonymous user may only have one session so do not store session list for anon user
	// This affects the way we retrieve sessions per user, see UserGetSessions()
	if !anon {
		err = sm.UserAppendSession(uid, &sess)
		if err != nil {
			return nil, err
		}
	}
	return &sess, nil
}

func (sm StandardSessionManager) DeleteSession(id string) error {
	value, err := sm.Store.Get("id2sess", id)
	if err != nil {
		return err
	}
	var sessions []Session
	if value != nil {
		sessions = value.([]Session)
	}
	// delete session from the list per user
	for _, sess := range sessions {
		uid := sess.UID
		err = sm.UserRemoveSession(uid, &sess)
		if err != nil {
			return err
		}
	}
	// delete actual session
	err = sm.Store.Delete("id2sess", id)
	if err != nil {
		return err
	}
	// also delete last accessed timestamp
	err = sm.Store.Delete("id2accessed", id)
	if err != nil {
		return err
	}
	return err
}

// return list of sessions linked to the user
// some may be expired, some may already be deleted from the Store
// also the sessions stored here have no updated Accessed field
// use only for list of session ids
func (sm StandardSessionManager) UserGetSessions(uid string) (sessions []Session, err error) {
	value, err := sm.Store.Get("uid2sess", uid)
	if err != nil {
		return nil, err
	}
	if value != nil {
		sessions = value.([]Session)
	} else {
		// only non-anonymous users' sessions are stored in session list
		// for anon try to find a single session
		if validID(uid) {
			// anon user has uid=sid
			sid := uid
			value, err := sm.Store.Get("id2sess", sid)
			if err != nil {
				return nil, err
			}
			if value != nil {
				sessions = value.([]Session)
			}
		}
	}
	return sessions, nil
}

func (sm StandardSessionManager) UserAppendSession(uid string, sess *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	value, err := sm.Store.Get("uid2sess", uid)
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
	return sm.Store.Put("uid2sess", uid, sessions)
}

func (sm StandardSessionManager) UserRemoveSession(uid string, sess *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	value, err := sm.Store.Get("uid2sess", uid)
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
	return sm.Store.Put("uid2sess", uid, newsessions)
}

// return empty string if session not found for device
// return only valid existing session
func (sm *StandardSessionManager) CurrentSessionForDevice(device Hasher) (id string, err error) {
	// first try to find named session id
	value, err := sm.Store.Get("device2sid", device.Hash())
	if err != nil {
		return "", err
	}
	if value != nil {
		id := value.(string)
		if id == "" {
			return "", nil
		}
		// return session id only if it is valid
		session, err := sm.GetSession(id)
		if err != nil {
			return "", err
		}
		if session != nil {
			return id, nil
		}
	}
	// otherwise try to find anonymous session
	value, err = sm.Store.Get("device2bid", device.Hash())
	if err != nil {
		return "", err
	}
	if value != nil {
		id := value.(string)
		if id == "" {
			return "", nil
		}
		// return session id only if it is valid
		session, err := sm.GetSession(id)
		if err != nil {
			return "", err
		}
		if session != nil {
			return id, nil
		}
	}
	return "", nil
}

func (sm *StandardSessionManager) GetDeviceForSession(id string) (device Hasher, err error) {
	if id == "" {
		return nil, nil
	}
	// first check if session is not expired by calling GetSession (which deletes expired sessions)
	session, err := sm.GetSession(id)
	if err != nil {
		return nil, err
	}
	if session == nil {
		sm.DeleteDeviceForSession(id, device)
		return nil, nil
	}
	// now if session exists search for device
	value, err := sm.Store.Get("id2device", id)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	device = value.(Hasher)
	// on a single device multiple sessions could have been created
	// return the device only when this is a device for its CURRENT session
	// that is valid (exists as per GetSession())
	deviceSessionId, err := sm.CurrentSessionForDevice(device)
	if err != nil {
		return nil, err
	}
	if deviceSessionId == "" {
		return nil, nil
	}
	if deviceSessionId == id {
		return device, nil
	}
	return nil, nil
}

func (sm *StandardSessionManager) SetDeviceForSession(session *Session, device Hasher) error {
	id := session.ID
	err := sm.Store.Put("id2device", id, device)
	if err != nil {
		return err
	}
	//save last session id that the device was attached to
	if session.Anon {
		return sm.Store.Put("device2bid", device.Hash(), id)
	} else {
		return sm.Store.Put("device2sid", device.Hash(), id)
	}
}

func (sm *StandardSessionManager) DeleteDeviceForSession(sessionid string, device Hasher) error {
	err := sm.Store.Delete("id2device", sessionid)
	if err != nil {
		return err
	}
	dhash := device.Hash()
	err = sm.Store.Delete("device2bid", dhash)
	if err != nil {
		return err
	}
	err = sm.Store.Delete("device2sid", dhash)
	if err != nil {
		return err
	}
	return nil
}
