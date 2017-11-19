package loginero

import (
	crand "crypto/rand"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
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
	userStore := NewRamUserStore()
	ssm := &StandardSessionManager{
		store: sessionStore,
	}
	sum := &StandardUserManager{
		store: userStore,
	}
	spe := &StandardParamExtractor{}
	defaultInstance = &Loginero{
		SessMan: ssm,
		UserMan: sum,
		ParamEx: spe,
	}
}

type Loginero struct {
	SessMan SessionManager
	UserMan UserManager
	ParamEx ParamExtractor
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
		uid, pass, err := loginero.ParamEx.ExtractLogin(r)
		if err != nil {
			wrapContext(loginHandler, nil, err)
			return
		}
		valid, err := loginero.UserMan.CredsValid(uid, pass)
		if err != nil {
			wrapContext(loginHandler, nil, err)
			return
		}

		if valid {
			sid := generateID()
			setSIDCookie(w, sid)
			sess, err := loginero.SessMan.CreateSession(sid, uid)
			wrapContext(loginHandler, sess, err)
			return
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			bid, sess, err := loginero.browserSessionFallback(r)
			setBIDCookie(w, bid)
			wrapContext(loginHandler, sess, err)
			return
		}
	}
}

func CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.CreateAccountController(createAccountHandler)
}

func (loginero *Loginero) CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, user, err := loginero.ParamEx.ExtractNewUser(r)
		if err != nil {
			wrapContext(createAccountHandler, nil, err)
			return
		}
		created, err := loginero.UserMan.CreateUser(user)
		if err != nil {
			wrapContext(createAccountHandler, nil, err)
			return
		}
		if created {
			sid := generateID()
			setSIDCookie(w, sid)
			sess, err := loginero.SessMan.CreateSession(sid, uid)
			wrapContext(createAccountHandler, sess, err)
			return
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			bid, sess, err := loginero.browserSessionFallback(r)
			setBIDCookie(w, bid)
			wrapContext(createAccountHandler, sess, err)
			return
		}
	}
}

func ResetPasswordController(resetHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.ResetPasswordController(resetHandler)
}

func (loginero *Loginero) ResetPasswordController(resetHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, pass, err := loginero.ParamEx.ExtractTokenPass(r)
		if err != nil {
			wrapContext(resetHandler, nil, err)
			return
		}
		sess, err := loginero.SessMan.FetchBound(token)
		if err != nil {
			wrapContext(resetHandler, nil, err)
			return
		}
		if sess != nil {
			updated, err := loginero.UserMan.UpdatePassword(sess.UID, pass)
			if err != nil {
				wrapContext(resetHandler, nil, err)
				return
			}
			if updated {
				sid := generateID()
				setSIDCookie(w, sid)
				sess, err := loginero.SessMan.CreateSession(sid, sess.UID)
				wrapContext(resetHandler, sess, err)
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
		wrapContext(resetHandler, sess, err)
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
				wrapContext(pageHandler, nil, err)
				return
			}
			if sess != nil {
				setSIDCookie(w, sid)
				wrapContext(pageHandler, sess, nil)
				return
			} else {
				deleteSIDCookie(w)
			}
		}
		bid, sess, err := loginero.browserSessionFallback(r)
		setBIDCookie(w, bid)
		wrapContext(pageHandler, sess, err)
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
		wrapContext(logoutHandler, sess, err)
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
