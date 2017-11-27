package loginero

import (
	crand "crypto/rand"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
	"sync"
	"time"
)

func p3(fs string, args ...interface{}) {
	log.Printf(fs+"\n", args...)
}

func init() {
	seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	mrand.Seed(seed.Int64())

	// we use 3 simplest RAM Key-Value stores here
	// but in production it may be a different storage base
	// since theses stores have different requirements
	sessionStore := StoreAdapter{NewRamStore()}
	userStore := StoreAdapter{NewRamStore()}
	ssm := &StandardSessionManager{
		Store: sessionStore,
	}
	sum := &StandardUserManager{
		Store: userStore,
	}
	extractor := &StandardUserExtractor{}
	DefaultInstance = &Loginero{
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

var DefaultInstance *Loginero

func IsTokenExpired(created time.Time) bool {
	return time.Now().Sub(created) > 30*time.Minute
}

func IsNamedSessionExpired(accessed time.Time) bool {
	return time.Now().Sub(accessed) > 3*time.Hour
}
func IsAnonSessionExpired(accessed time.Time) bool {
	return time.Now().Sub(accessed) > 365*24*time.Hour
}
func IsSessionExpired(accessed time.Time, anon bool) bool {
	if anon {
		return IsAnonSessionExpired(accessed)
	} else {
		return IsNamedSessionExpired(accessed)
	}
}

func CurrentSession(r *http.Request) (*Session, error) {
	return DefaultInstance.CurrentSession(r)
}

func UserToken(uid string) (token string, err error) {
	return DefaultInstance.UserToken(uid)
}

func (lo *Loginero) UserToken(uid string) (token string, err error) {
	exists, err := lo.UserMan.UserExists(uid)
	if err == nil && exists {
		token, err = lo.SessMan.BindToken(uid)
	}
	return token, err
}

func GetDeviceForSession(id string) (device Hasher, err error) {
	return DefaultInstance.GetDeviceForSession(id)
}

func (lo *Loginero) GetDeviceForSession(id string) (device Hasher, err error) {
	return lo.SessMan.GetDeviceForSession(id)
}
func SetDeviceForSession(session *Session, device Hasher) error {
	return DefaultInstance.SetDeviceForSession(session, device)
}
func (lo *Loginero) SetDeviceForSession(session *Session, device Hasher) error {
	return lo.SessMan.SetDeviceForSession(session, device)
}
func UserGetSessions(uid string) (sessions []Session, err error) {
	return DefaultInstance.UserGetSessions(uid)
}
func (lo *Loginero) UserGetSessions(uid string) (sessions []Session, err error) {
	return lo.SessMan.UserGetSessions(uid)
}

func LoginController(loginHandler http.HandlerFunc) http.HandlerFunc {
	return DefaultInstance.LoginController(loginHandler)
}

func (lo *Loginero) LoginController(loginHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, pass, err := lo.Extractor.ExtractUserPass(r)
		if err != nil {
			lo.wrapContext(loginHandler, &Context{nil, err})(w, r)
			return
		}
		valid, err := lo.UserMan.CredsValid(uid, pass)
		if err != nil {
			lo.wrapContext(loginHandler, &Context{nil, err})(w, r)
			return
		}

		if valid {
			sid := GenerateID()
			setSIDCookie(w, sid)
			sess, err := lo.SessMan.CreateSession(sid, uid, false)
			lo.wrapContext(loginHandler, &Context{sess, err})(w, r)
			return
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				lo.SessMan.DeleteSession(sid)
			}
			bid, sess, err := lo.browserSessionFallback(r)
			setBIDCookie(w, bid)
			lo.wrapContext(loginHandler, &Context{sess, err})(w, r)
			return
		}
	}
}

func CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return DefaultInstance.CreateAccountController(createAccountHandler)
}

func (lo *Loginero) CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, pass, err := lo.Extractor.ExtractUserPass(r)
		if err != nil {
			lo.wrapContext(createAccountHandler, &Context{nil, err})(w, r)
			return
		}
		created, err := lo.UserMan.CreateUser(uid, pass)
		if err != nil {
			lo.wrapContext(createAccountHandler, &Context{nil, err})(w, r)
			return
		}
		if created {
			sid := GenerateID()
			setSIDCookie(w, sid)
			sess, err := lo.SessMan.CreateSession(sid, uid, false)
			lo.wrapContext(createAccountHandler, &Context{sess, err})(w, r)
			return
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				lo.SessMan.DeleteSession(sid)
			}
			bid, sess, err := lo.browserSessionFallback(r)
			setBIDCookie(w, bid)
			lo.wrapContext(createAccountHandler, &Context{sess, err})(w, r)
			return
		}
	}
}

func ResetPasswordController(resetHandler http.HandlerFunc) http.HandlerFunc {
	return DefaultInstance.ResetPasswordController(resetHandler)
}

func (lo *Loginero) ResetPasswordController(resetHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, pass, err := lo.Extractor.ExtractTokenPass(r)
		if err != nil {
			lo.wrapContext(resetHandler, &Context{nil, err})(w, r)
			return
		}
		sess, err := lo.SessMan.FetchBound(token)
		if err != nil {
			lo.wrapContext(resetHandler, &Context{nil, err})(w, r)
			return
		}
		if sess != nil && !IsTokenExpired(sess.Created) {
			updated, err := lo.UserMan.UpdatePassword(sess.UID, pass)
			if err != nil {
				lo.wrapContext(resetHandler, &Context{nil, err})(w, r)
				return
			}
			if updated {
				// TODO should we deactivate all other sessions related to uid?
				sid := GenerateID()
				setSIDCookie(w, sid)
				sess, err := lo.SessMan.CreateSession(sid, sess.UID, false)
				lo.wrapContext(resetHandler, &Context{sess, err})(w, r)
				return
			}
		}

		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			lo.SessMan.DeleteSession(sid)
		}
		bid, sess, err := lo.browserSessionFallback(r)
		setBIDCookie(w, bid)
		lo.wrapContext(resetHandler, &Context{sess, err})(w, r)
		return
	}
}

func PageController(pageHandler http.HandlerFunc) http.HandlerFunc {
	return DefaultInstance.PageController(pageHandler)
}

func (lo *Loginero) PageController(pageHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := getRequestSID(r)
		if sid != "" {
			sess, err := lo.SessMan.GetSession(sid)
			if err == nil && sess != nil {
				err = lo.SessMan.AccessSession(sid)
			}
			if err != nil {
				lo.wrapContext(pageHandler, &Context{nil, err})(w, r)
				return
			}
			if sess != nil {
				setSIDCookie(w, sid)
				lo.wrapContext(pageHandler, &Context{sess, nil})(w, r)
				return
			} else {
				deleteSIDCookie(w)
			}
		}
		bid, sess, err := lo.browserSessionFallback(r)
		setBIDCookie(w, bid)
		lo.wrapContext(pageHandler, &Context{sess, err})(w, r)
		return
	}
}

func LogoutController(logoutHandler http.HandlerFunc) http.HandlerFunc {
	return DefaultInstance.LogoutController(logoutHandler)
}

func (lo *Loginero) LogoutController(logoutHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			lo.SessMan.DeleteSession(sid)
		}
		bid, sess, err := lo.browserSessionFallback(r)
		setBIDCookie(w, bid)
		lo.wrapContext(logoutHandler, &Context{sess, err})(w, r)
		return
	}
}

func (lo *Loginero) browserSessionFallback(r *http.Request) (bid string, sess *Session, err error) {
	// fallback - pass anonymous browser user
	bid = getRequestBID(r)
	if bid == "" {
		bid = GenerateID()
		// create anonymous session with uid=bid
		err = lo.UserMan.CreateAnonUser(bid)
		if err == nil {
			sess, err = lo.SessMan.CreateSession(bid, bid, true)
		}
	} else {
		// get anonymous session
		sess, err = lo.SessMan.GetSession(bid)
		if err == nil && sess != nil {
			err = lo.SessMan.AccessSession(bid)
		}
		if err == nil && sess == nil {
			bid = GenerateID()
			// create anonymous session with uid=bid
			err = lo.UserMan.CreateAnonUser(bid)
			if err == nil {
				sess, err = lo.SessMan.CreateSession(bid, bid, true)
			}
		}

	}
	return bid, sess, err
}
