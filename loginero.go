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
	sessionStore := NewRamStore()
	userStore := NewRamStore()
	deviceStore := NewRamStore()
	ssm := &StandardSessionManager{
		Store: sessionStore,
	}
	sum := &StandardUserManager{
		Store: userStore,
	}
	extractor := &StandardUserExtractor{}
	sdm := &StandardDeviceManager{
		Store: deviceStore,
	}
	DefaultInstance = &Loginero{
		SessMan:   ssm,
		UserMan:   sum,
		Extractor: extractor,
		DeviceMan: sdm,
		context:   make(map[*http.Request]*Context),
	}
}

type Loginero struct {
	SessMan      SessionManager
	UserMan      UserManager
	Extractor    UserExtractor
	DeviceMan    DeviceManager
	context      map[*http.Request]*Context
	contextMutex sync.RWMutex
}

type Context struct {
	sess *Session
	err  error
}

var DefaultInstance *Loginero
var tokenExpireTime = 30 * time.Minute

func CurrentSession(r *http.Request) (*Session, error) {
	return DefaultInstance.CurrentSession(r)
}

func UserToken(uid string) (token string, err error) {
	return DefaultInstance.UserToken(uid)
}

func (loginero *Loginero) UserToken(uid string) (token string, err error) {
	exists, err := loginero.UserMan.UserExists(uid)
	if err == nil && exists {
		token, err = loginero.SessMan.BindToken(uid)
	}
	return token, err
}

func GetDeviceForSession(sid string) (device interface{}, err error) {
	return DefaultInstance.DeviceMan.GetDeviceForSession(sid)
}

func SetDeviceForSession(sid string, device interface{}) error {
	return DefaultInstance.DeviceMan.SetDeviceForSession(sid, device)
}

func UserGetSessions(uid string) (sessions []Session, err error) {
	return DefaultInstance.SessMan.UserGetSessions(uid)
}

func LoginController(loginHandler http.HandlerFunc) http.HandlerFunc {
	return DefaultInstance.LoginController(loginHandler)
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
			sess, err := loginero.SessMan.CreateSession(sid, uid, false)
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
	return DefaultInstance.CreateAccountController(createAccountHandler)
}

func (loginero *Loginero) CreateAccountController(createAccountHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, pass, user, err := loginero.Extractor.ExtractNewUser(r)
		if err != nil {
			loginero.wrapContext(createAccountHandler, &Context{nil, err})(w, r)
			return
		}
		created, err := loginero.UserMan.CreateUser(user, pass)
		if err != nil {
			loginero.wrapContext(createAccountHandler, &Context{nil, err})(w, r)
			return
		}
		if created {
			sid := generateID()
			setSIDCookie(w, sid)
			sess, err := loginero.SessMan.CreateSession(sid, uid, false)
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
	return DefaultInstance.ResetPasswordController(resetHandler)
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
		if sess != nil && time.Now().Sub(sess.Created) < tokenExpireTime {
			updated, err := loginero.UserMan.UpdatePassword(sess.UID, pass)
			if err != nil {
				loginero.wrapContext(resetHandler, &Context{nil, err})(w, r)
				return
			}
			if updated {
				// TODO should we deactivate all other sessions related to uid?
				sid := generateID()
				setSIDCookie(w, sid)
				sess, err := loginero.SessMan.CreateSession(sid, sess.UID, false)
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
	return DefaultInstance.PageController(pageHandler)
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
	return DefaultInstance.LogoutController(logoutHandler)
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
		// create anonymous session with uid=bid
		sess, err = loginero.SessMan.CreateSession(bid, bid, true)
	} else {
		// get anonymous session
		sess, err = loginero.SessMan.GetSession(bid)
		if err == nil && sess == nil {
			bid = generateID()
			// create anonymous session with uid=bid
			sess, err = loginero.SessMan.CreateSession(bid, bid, true)
		}
	}
	return bid, sess, err
}
