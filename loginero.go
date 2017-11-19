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

func LoginController(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return defaultInstance.LoginController(redirectSuccess, redirectFail)
}

func (loginero *Loginero) LoginController(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)

		var err error
		valid := false
		uid, pass, err := loginero.ParamEx.ExtractLogin(r)
		if err == nil {
			valid, err = loginero.UserMan.CredsValid(uid, pass, bid)
		}

		if err == nil && valid {
			sid := generateID()
			setSIDCookie(w, sid)
			loginero.SessMan.CreateSession(sid, uid)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
			return
		} else {

			//TODO check err and return error code in redirectFail
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
			return
		}
	}
}

func CreateAccountController(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return defaultInstance.CreateAccountController(redirectSuccess, redirectFail)
}

func (loginero *Loginero) CreateAccountController(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)
		var err error
		created := false
		uid, user, err := loginero.ParamEx.ExtractNewUser(r)
		if err == nil {
			created, err = loginero.UserMan.CreateUser(user, bid)
		}
		if user != nil && err == nil && created {
			sid := generateID()
			setSIDCookie(w, sid)
			loginero.SessMan.CreateSession(sid, uid)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			//TODO check err and return error code in redirectFail

			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
	}
}

func ResetPasswordController(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return defaultInstance.ResetPasswordController(redirectSuccess, redirectFail)
}

func (loginero *Loginero) ResetPasswordController(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)

		updated := false
		var sess *Session
		token, pass, err := loginero.ParamEx.ExtractTokenPass(r)
		if err == nil {
			sess, err = loginero.SessMan.FetchBound(token, bid)
			if err == nil && sess != nil {
				updated, err = loginero.UserMan.UpdatePassword(sess.UID, pass)
			}
		}

		if err == nil && sess != nil && updated {
			sid := generateID()
			setSIDCookie(w, sid)
			loginero.SessMan.CreateSession(sid, sess.UID)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				loginero.SessMan.DeleteSession(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
	}
}

func PageController(pageHandler http.HandlerFunc) http.HandlerFunc {
	return defaultInstance.PageController(pageHandler)
}

func (loginero *Loginero) PageController(pageHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var sess *Session
		sid := getRequestSID(r)
		if sid != "" {
			sess, err = loginero.SessMan.GetSession(sid)
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
		// err and sess are nil here
		// fallback - pass anonymous browser user
		bid := getRequestBID(r)
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
		setBIDCookie(w, bid)
		wrapContext(pageHandler, sess, err)
		return
	}
}

func LogoutController(redirectSuccess string) http.HandlerFunc {
	return defaultInstance.LogoutController(redirectSuccess)
}

func (loginero *Loginero) LogoutController(redirectSuccess string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)
		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			loginero.SessMan.DeleteSession(sid)
		}
		http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
	}
}
