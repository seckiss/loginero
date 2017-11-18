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
// - UserStore API to return identity (unique user string like username/email)
// and have another Get/Set methods to access actual
// - split store to SessionStore and UserStore
// - Configuration options: passing UserStore
// - the only external interface/API should be a key-value store

func init() {
	seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	mrand.Seed(seed.Int64())
}

func SetOptions() {
	//TODO set BID and SID cookie template (Path, Secure, HttpOnly, MaxAge, etc)
}

/////////////////////////////////////////////////////
/////////////////////////////////////////////////
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
				token, err = dsm.BindToken(uid)
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
