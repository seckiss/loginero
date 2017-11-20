package loginero

import (
	crand "crypto/rand"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
	"sync"
)

//TODO:
// There are a few missing features:
// 1) Terminate all sessions of the user
// 2) Remove stale records in Sid2User after password reset (related to no 1)
// 3) reporting errors from UserStore - need API change
// 4) use different UserStore than default

// To solve the above need to change API and implementation:
// - UserStore API to return errors
// - Configuration options: passing UserStore
// - the only external interface/API should be a key-value store

func init() {
	seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	mrand.Seed(seed.Int64())

	sessionStore := NewRamSessionStore()
	userStore := NewRamStore()
	ssm := &StandardSessionManager{
		store: sessionStore,
	}
	sum := &StandardUserManager{
		store: userStore,
	}
	extractor := &StandardUserExtractor{}
	defaultInstance = &Loginero{
		SessMan:   ssm,
		UserMan:   sum,
		Extractor: extractor,
		context:   make(map[*http.Request]*Context),
	}
}

type Loginero struct {
	SessMan      SessionManager
	UserMan      UserManager
	Extractor    UserExtractor
	context      map[*http.Request]*Context
	contextMutex sync.RWMutex
}

type Context struct {
	sess *Session
	err  error
}

var defaultInstance *Loginero

func SetOptions() {
	//TODO set BID and SID cookie template (Path, Secure, HttpOnly, MaxAge, etc)
}

func BindToken(uid string) (token string, err error) {
	return defaultInstance.SessMan.BindToken(uid)
}

func (loginero *Loginero) BindToken(uid string) (token string, err error) {
	return loginero.SessMan.BindToken(uid)
}

func LoginController(loginHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.LoginController(loginHandler)
}

func (loginero *Loginero) LoginController(loginHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, pass, err := loginero.Extractor.ExtractLogin(r)
		if err != nil {
			loginero.wrapContext(loginHandler, &Context{nil, err})(w, r)
			return
		}
		valid, err := loginero.UserMan.CredsValid(uid, pass)
		if err != nil {
			loginero.wrapContext(loginHandler, &Context{nil, err})(w, r)
			return
		}

		if valid {
			sid := generateID()
			setSIDCookie(w, sid)
			sess, err := loginero.SessMan.CreateSession(sid, uid)
			loginero.wrapContext(loginHandler, &Context{sess, err})(w, r)
			return
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			bid, sess, err := loginero.browserSessionFallback(r)
			setBIDCookie(w, bid)
			loginero.wrapContext(loginHandler, &Context{sess, err})(w, r)
			return
		}
	}
}

func CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.CreateAccountController(createAccountHandler)
}

func (loginero *Loginero) CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, user, err := loginero.Extractor.ExtractNewUser(r)
		if err != nil {
			loginero.wrapContext(createAccountHandler, &Context{nil, err})(w, r)
			return
		}
		created, err := loginero.UserMan.CreateUser(user)
		if err != nil {
			loginero.wrapContext(createAccountHandler, &Context{nil, err})(w, r)
			return
		}
		if created {
			sid := generateID()
			setSIDCookie(w, sid)
			sess, err := loginero.SessMan.CreateSession(sid, uid)
			loginero.wrapContext(createAccountHandler, &Context{sess, err})(w, r)
			return
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			bid, sess, err := loginero.browserSessionFallback(r)
			setBIDCookie(w, bid)
			loginero.wrapContext(createAccountHandler, &Context{sess, err})(w, r)
			return
		}
	}
}

func ResetPasswordController(resetHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.ResetPasswordController(resetHandler)
}

func (loginero *Loginero) ResetPasswordController(resetHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, pass, err := loginero.Extractor.ExtractTokenPass(r)
		if err != nil {
			loginero.wrapContext(resetHandler, &Context{nil, err})(w, r)
			return
		}
		sess, err := loginero.SessMan.FetchBound(token)
		if err != nil {
			loginero.wrapContext(resetHandler, &Context{nil, err})(w, r)
			return
		}
		if sess != nil {
			updated, err := loginero.UserMan.UpdatePassword(sess.UID, pass)
			if err != nil {
				loginero.wrapContext(resetHandler, &Context{nil, err})(w, r)
				return
			}
			if updated {
				sid := generateID()
				setSIDCookie(w, sid)
				sess, err := loginero.SessMan.CreateSession(sid, sess.UID)
				loginero.wrapContext(resetHandler, &Context{sess, err})(w, r)
				return
			}
		}

		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			loginero.SessMan.DeleteSession(sid)
		}
		bid, sess, err := loginero.browserSessionFallback(r)
		setBIDCookie(w, bid)
		loginero.wrapContext(resetHandler, &Context{sess, err})(w, r)
		return
	}
}

func PageController(pageHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.PageController(pageHandler)
}

func (loginero *Loginero) PageController(pageHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := getRequestSID(r)
		if sid != "" {
			sess, err := loginero.SessMan.GetSession(sid)
			if err != nil {
				loginero.wrapContext(pageHandler, &Context{nil, err})(w, r)
				return
			}
			if sess != nil {
				setSIDCookie(w, sid)
				loginero.wrapContext(pageHandler, &Context{sess, nil})(w, r)
				return
			} else {
				deleteSIDCookie(w)
			}
		}
		bid, sess, err := loginero.browserSessionFallback(r)
		setBIDCookie(w, bid)
		loginero.wrapContext(pageHandler, &Context{sess, err})(w, r)
		return
	}
}

func LogoutController(logoutHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.LogoutController(logoutHandler)
}

func (loginero *Loginero) LogoutController(logoutHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			loginero.SessMan.DeleteSession(sid)
		}
		bid, sess, err := loginero.browserSessionFallback(r)
		setBIDCookie(w, bid)
		loginero.wrapContext(logoutHandler, &Context{sess, err})(w, r)
		return
	}
}

func (loginero *Loginero) browserSessionFallback(r *http.Request) (bid string, sess *Session, err error) {
	// fallback - pass anonymous browser user
	bid = getRequestBID(r)
	if bid == "" {
		bid = generateID()
		sess, err = loginero.SessMan.CreateAnonSession(bid)
	} else {
		sess, err = loginero.SessMan.GetAnonSession(bid)
		if err == nil && sess == nil {
			bid = generateID()
			sess, err = loginero.SessMan.CreateAnonSession(bid)
		}
	}
	return bid, sess, err
}
