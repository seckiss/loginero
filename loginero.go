package loginero

import (
	crand "crypto/rand"
	"errors"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
	"regexp"
	"sync"
	"time"
)

//TODO:
// There are a few missing features:
// 1) Terminate all sessions of the user
// 2) Remove stale records in Sid2User after password reset (related to no 1)
// 3) reporting errors from UserStore - need API change
// 4) use different UserStore than default

// To solve the above need to change API and implementation:
// - UserStore API to return errors
// - UserStore API to return identity (unique user string like username/email)
// and have another Get/Set methods to access actual
// - split store to SessionStore and UserStore
// - Configuration options: passing UserStore
// - the only external interface/API should be a key-value store

var b62ascii = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62regexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

//var defaultUserStore = NewRamUserStore()
var dsm SessionManager
var dum UserManager
var dpe ParamExtractor
var sidName = "LO_SID"
var bidName = "LO_BID"
var contextSession = make(map[*http.Request]*Session)
var contextSessionMutex sync.RWMutex
var contextToken = make(map[*http.Request]string)
var contextTokenMutex sync.RWMutex

func init() {
	seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	mrand.Seed(seed.Int64())
}

// Generate random string
// 16-chars of base62 gives about 95.3 bits of entropy
// This gives the space of about 10^10 generated ids with probability of collision = 10^-9 according to birthday paradox calcs
func generateID() string {
	var b = make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[i] = b62ascii[mrand.Intn(62)]
	}
	return string(b)
}

func CurrentSession(r *http.Request) interface{} {
	contextSessionMutex.RLock()
	defer contextSessionMutex.RUnlock()
	return contextSession[r]
}

func Token(r *http.Request) string {
	contextTokenMutex.RLock()
	defer contextTokenMutex.RUnlock()
	return contextToken[r]
}

func SetOptions() {
	//TODO set BID and SID cookie template (Path, Secure, HttpOnly, MaxAge, etc)
}

type Session struct {
	UID     string
	Created time.Time
	Anon    bool
}

type User interface {
	GetUID() string
	CheckPassword(pass string) bool
}
type SimpleUser struct {
	UID      string
	Password string
}

func (u *SimpleUser) GetUID() string {
	return u.UID
}

func (u *SimpleUser) CheckPassword(pass string) bool {
	return pass == u.Password
}

/////////////////////////////////////////////////////

type SessionStore interface {
	Get(k string) (*Session, error)
	Set(k string, s *Session) error
	Delete(k string) error
}

type SessionManager interface {
	// use identity (username, email, etc) from the request to find user in the db
	// and bind it to the token
	// return bound user or nil if user not found
	BindToken(uid string, bid string) (token string, err error)
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

type ParamExtractor interface {
	ExtractNewUser(r *http.Request) (User, error)
	ExtractLogin(r *http.Request) (uid string, pass string, err error)
	ExtractPassReset(r *http.Request) (pass string, token string, err error)
	ExtractUsername(r *http.Request) (uid string, err error)
}

type StandardParamExtractor struct {
}

func (pe *StandardParamExtractor) ExtractNewUser(r *http.Request) (User, error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if username != "" && pass1 != "" && pass1 == pass2 {
		return &SimpleUser{UID: username, Password: pass1}, nil
	}
	return nil, errors.New("Wrong POST params")
}

func (pe *StandardParamExtractor) ExtractLogin(r *http.Request) (uid string, pass string, err error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	if username != "" && pass1 != "" {
		return username, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")

}

func (pe *StandardParamExtractor) ExtractPassReset(r *http.Request) (pass string, token string, err error) {
	token = r.FormValue("token")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if token != "" && pass1 != "" && pass1 == pass2 {
		return pass1, token, nil
	}
	return "", "", errors.New("Wrong POST params")
}

func (pe *StandardParamExtractor) ExtractUsername(r *http.Request) (uid string, err error) {
	username := r.FormValue("username")
	if username != "" {
		return username, nil
	}
	return "", errors.New("Wrong POST params")
}

type UserManager interface {
	UserExists(uid string) (bool, error)
	UpdatePassword(uid string, pass string) (bool, error)
	CreateUser(u User, bid string) (bool, error)
	CredsValid(uid string, pass string, bid string) (bool, error)
}

type UserStore interface {
	Get(uid string) (User, error)
	Set(uid string, u User) error
}

type StandardUserManager struct {
	store UserStore
}

func (um *StandardUserManager) UserExists(uid string) (bool, error) {
	//TODO implement
	return false, nil
}

func (um *StandardUserManager) UpdatePassword(uid string, pass string) (bool, error) {
	//TODO implement
	return false, nil
}

func (um *StandardUserManager) CreateUser(u User, bid string) (bool, error) {
	//TODO create user if uid does not exist
	//			newuser := SimpleUser{UID: username, Password: pass1}
	//			um.store.Set(username, &newuser)
	return false, nil
}

func (um *StandardUserManager) CredsValid(uid string, pass string, bid string) (bool, error) {
	// TODO uid and password check
	//			if user.CheckPassword(pass1) {
	return false, nil
}

/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
// Handlers
/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////

func LoginHandler(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)

		var err error
		valid := false
		uid, pass, err := dpe.ExtractLogin(r)
		if err == nil {
			valid, err = dum.CredsValid(uid, pass, bid)
		}

		if err == nil && valid {
			sid := generateID()
			setSIDCookie(w, sid)
			dsm.CreateSession(sid, uid)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
			return
		} else {

			//TODO check err and return error code in redirectFail
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				dsm.DeleteSessionUser(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
			return
		}
	}
}

func CreateAccountHandler(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)
		var err error
		created := false
		user, err := dpe.ExtractNewUser(r)
		if err == nil {
			created, err = dum.CreateUser(user, bid)
		}
		if user != nil && err == nil && created {
			sid := generateID()
			setSIDCookie(w, sid)
			dsm.CreateSession(sid, user.GetUID())
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			//TODO check err and return error code in redirectFail

			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				dsm.DeleteSessionUser(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
	}
}

func ResetPasswordHandler(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)

		updated := false
		var sess *Session
		pass, token, err := dpe.ExtractPassReset(r)
		if err == nil {
			sess, err = dsm.FetchBound(token, bid)
			if err == nil && sess != nil {
				updated, err = dum.UpdatePassword(sess.UID, pass)
			}
		}

		if err == nil && sess != nil && updated {
			sid := generateID()
			setSIDCookie(w, sid)
			dsm.CreateSession(sid, sess.UID)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				dsm.DeleteSessionUser(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
	}
}

// Bind one-time token to user
// Bound token is passed in context
// The token is empty string if user not found
func ForgotPasswordHandler(passtokenHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)

		var token string
		var err error
		uid, err := dpe.ExtractUsername(r)
		if err == nil && uid != "" {
			exists, err := dum.UserExists(uid)
			if err == nil && exists {
				token, err = dsm.BindToken(uid, bid)
			}
		}

		// save token in context
		contextTokenMutex.Lock()
		contextToken[r] = token
		contextTokenMutex.Unlock()

		passtokenHandler(w, r)

		// delete token in context
		contextTokenMutex.Lock()
		delete(contextToken, r)
		contextTokenMutex.Unlock()
	}
}

func LogoutHandler(redirectSuccess string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)
		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			dsm.DeleteSessionUser(sid)
		}
		http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
	}
}

func PageHandler(loggedHandler http.HandlerFunc, unloggedHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var sess *Session
		sid := getRequestSID(r)
		if sid != "" {
			sess, err = dsm.GetSession(sid)
			//TODO handle error
			if err == nil {
				if sess != nil {
					setSIDCookie(w, sid)

					//save session in context
					contextSessionMutex.Lock()
					contextSession[r] = sess
					contextSessionMutex.Unlock()

					loggedHandler(w, r)

					//delete session from context
					contextSessionMutex.Lock()
					delete(contextSession, r)
					contextSessionMutex.Unlock()

					return
				} else {
					deleteSIDCookie(w)
				}
			}
		}
		// TODO handle error, think it over
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
			sess, err = dsm.CreateAnonSession(bid)
		} else {
			sess, err = dsm.GetAnonSession(bid)
			if sess == nil {
				bid = generateID()
				sess, err = dsm.CreateAnonSession(bid)
			}
		}
		setBIDCookie(w, bid)

		//save session in context
		contextSessionMutex.Lock()
		contextSession[r] = sess
		contextSessionMutex.Unlock()

		unloggedHandler(w, r)

		//delete session from context
		contextSessionMutex.Lock()
		delete(contextSession, r)
		contextSessionMutex.Unlock()
	}
}

func getRequestBID(r *http.Request) string {
	c, err := r.Cookie(bidName)
	if err == nil && validatedID(c.Value) {
		return c.Value
	}
	return ""
}

func getRequestSID(r *http.Request) string {
	c, err := r.Cookie(sidName)
	if err == nil && validatedID(c.Value) {
		return c.Value
	}
	return ""
}

func validatedID(id string) bool {
	return len(id) == 16 && b62regexp.MatchString(id)
}

func setBIDCookie(w http.ResponseWriter, bid string) {
	//TODO cookie should be cloned from options' BID cookie template
	http.SetCookie(w, &http.Cookie{Name: bidName, Value: bid, MaxAge: 500000000, Path: "/"})
}

func setSIDCookie(w http.ResponseWriter, sid string) {
	//TODO cookie should be cloned from options' SID cookie template
	//session cookie, no max-age
	http.SetCookie(w, &http.Cookie{Name: sidName, Value: sid, Path: "/"})
}

func deleteBIDCookie(w http.ResponseWriter) {
	//TODO cookie should be cloned from options' BID cookie template
	http.SetCookie(w, &http.Cookie{Name: bidName, Value: "", MaxAge: -1, Path: "/"})
}
func deleteSIDCookie(w http.ResponseWriter) {
	//TODO cookie should be cloned from options' SID cookie template
	http.SetCookie(w, &http.Cookie{Name: sidName, Value: "", MaxAge: -1, Path: "/"})
}
