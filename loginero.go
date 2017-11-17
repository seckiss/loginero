package loginero

import (
	"net/http"

	crand "crypto/rand"
	"math"
	"math/big"
	mrand "math/rand"
	"regexp"
	"sync"
)

var b62ascii = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62regexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
var defaultUserStore = NewRamUserStore()
var sidName = "LO_SID"
var bidName = "LO_BID"

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
// This is public function because it may be used to generate one-time reset tokens for password reset
func GenerateID() string {
	var b = make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[i] = b62ascii[mrand.Intn(62)]
	}
	return string(b)
}

func SetOptions() {
	//TODO set BID and SID cookie template (Path, Secure, HttpOnly, MaxAge, etc)
}

/////////////////////////////////////////////////////
// Example implementation to be used for testing
// This is insecure, naive implementation of non-durable UserStore
/////////////////////////////////////////////////////

type SimpleUser struct {
	Username string
	Password string
}

type RamUserStore struct {
	// Registered user base with credentials (SimpleUser), uid = unique user id / username
	Uid2User map[string]interface{}
	UidMutex sync.RWMutex
	// Anonymous user base (SimpleUser)
	Bid2User map[string]interface{}
	BidMutex sync.RWMutex
	// Registered user session base (SimpleUser)
	Sid2User map[string]interface{}
	SidMutex sync.RWMutex
	// Registered users who can reset password (SimpleUser)
	// In full implementation entries should have expiry timeout
	ResetToken2User map[string]interface{}
	ResetMutex      sync.RWMutex
}

func NewRamUserStore() *RamUserStore {
	return &RamUserStore{
		Uid2User:        make(map[string]interface{}),
		Bid2User:        make(map[string]interface{}),
		Sid2User:        make(map[string]interface{}),
		ResetToken2User: make(map[string]interface{}),
	}
}

func (store *RamUserStore) CreateUserCreds(r *http.Request, bid string) interface{} {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if username != "" && pass1 == pass2 {
		store.UidMutex.Lock()
		defer store.UidMutex.Unlock()
		if _, pres := store.Uid2User[username]; !pres {
			// ok, username does not exist yet
			newuser := SimpleUser{Username: username, Password: pass1}
			store.Uid2User[username] = newuser
			return newuser
		}
	}
	return nil
}

func (store *RamUserStore) FindUserCreds(r *http.Request, bid string) interface{} {
	username := r.FormValue("username")
	if username != "" {
		store.UidMutex.RLock()
		defer store.UidMutex.RUnlock()
		if user, pres := store.Uid2User[username]; pres {
			return user
		}
	}
	return nil
}

func (store *RamUserStore) CheckUserCreds(r *http.Request, bid string) interface{} {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	if username != "" && pass1 != "" {
		store.UidMutex.RLock()
		defer store.UidMutex.RUnlock()
		if user, pres := store.Uid2User[username]; pres {
			if pass1 == user.(SimpleUser).Password {
				return user
			}
		}
	}
	return nil
}

func (store *RamUserStore) ResetUserCreds(r *http.Request, bid string) interface{} {
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	token := r.FormValue("token")
	if pass1 == pass2 {
		store.ResetMutex.Lock()
		defer store.ResetMutex.Unlock()
		user, pres := store.ResetToken2User[token]
		if pres {
			// it's one-time user token, so delete if found
			delete(store.ResetToken2User, token)
			updated := user.(SimpleUser)
			updated.Password = pass1
			// TODO check if need to update/remove record in Sid2User, Bid2User, Uid2User
			return updated
		}
	}
	return nil
}

func (store *RamUserStore) GetSessionUser(sid string) interface{} {
	if sid != "" {
		store.SidMutex.RLock()
		defer store.SidMutex.RUnlock()
		user, pres := store.Sid2User[sid]
		if pres {
			return user
		}
	}
	return nil
}

func (store *RamUserStore) GetBrowserUser(bid string) interface{} {
	if bid != "" {
		store.BidMutex.RLock()
		defer store.BidMutex.RUnlock()
		user, pres := store.Bid2User[bid]
		if pres {
			return user
		}
	}
	return nil
}

func (store *RamUserStore) SaveSessionUser(sid string, user interface{}) {
	if sid != "" {
		store.SidMutex.Lock()
		defer store.SidMutex.Unlock()
		store.Sid2User[sid] = user
	}
}

func (store *RamUserStore) CreateBrowserUser(bid string) interface{} {
	// For anonymous user we use the same struct as for logged user
	// This is an implementation detail (other implementations may return a different struct)
	if bid != "" {
		user := SimpleUser{Username: bid, Password: ""}
		store.BidMutex.Lock()
		defer store.BidMutex.Unlock()
		store.Bid2User[bid] = user
		return user
	}
	return nil
}

func (store *RamUserStore) DeleteSessionUser(sid string) {
	if sid != "" {
		store.SidMutex.Lock()
		defer store.SidMutex.Unlock()
		delete(store.Sid2User, sid)
	}
}

/////////////////////////////////////////////////////

type UserStore interface {
	// use credentials from the request to create the new user object
	// store it in db and return it (without credentials)
	// return nil if user already exists (unique by username/email/id etc)
	// the bid argument may be used to link the anonymous BrowserUser (BIDuser)
	// with the newly created account/user
	CreateUserCreds(r *http.Request, bid string) interface{}
	// use identity (username, email, etc) from the request to find user in the db
	FindUserCreds(r *http.Request, bid string) interface{}
	// use credentials from the request to find user in the db
	// check credentials, return user (without credentials) or nil if not found/not matching
	// the bid argument may be used to link the anonymous BrowserUser (BIDuser)
	// with the credential based logging in user
	CheckUserCreds(r *http.Request, bid string) interface{}
	// for password Reset
	// implementation needs to verify one-time reset token linked to particular user
	ResetUserCreds(r *http.Request, bid string) interface{}
	GetSessionUser(sid string) interface{}
	GetBrowserUser(bid string) interface{}
	SaveSessionUser(sid string, user interface{})
	CreateBrowserUser(bid string) interface{}
	DeleteSessionUser(sid string)
}

func LoginHandler(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = GenerateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.CheckUserCreds(r, bid)
		if user != nil {
			sid := GenerateID()
			setSIDCookie(w, sid)
			defaultUserStore.SaveSessionUser(sid, user)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				defaultUserStore.DeleteSessionUser(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
	}
}

func CreateAccountHandler(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = GenerateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.CreateUserCreds(r, bid)
		if user != nil {
			sid := GenerateID()
			setSIDCookie(w, sid)
			defaultUserStore.SaveSessionUser(sid, user)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				defaultUserStore.DeleteSessionUser(sid)
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
			bid = GenerateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.ResetUserCreds(r, bid)
		if user != nil {
			sid := GenerateID()
			setSIDCookie(w, sid)
			defaultUserStore.SaveSessionUser(sid, user)
			//TODO for AJAX API version instead of redirect give HTTP 200 OK response
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				defaultUserStore.DeleteSessionUser(sid)
			}
			//TODO for AJAX API version instead of redirect give HTTP 400 bad request response
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
	}
}

// Bind one-time token to user
func ForgotPasswordHandler(passtokenHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = GenerateID()
		}
		setBIDCookie(w, bid)

		user := defaultUserStore.FindUserCreds(r, bid)
		if user != nil {
			token := GenerateID()
			//TODO save token in context[r]
			_ = token
			passtokenHandler(w, r)
			//TODO delete token from context[r]
		}
	}
}

func LogoutHandler(redirectSuccess string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = GenerateID()
		}
		setBIDCookie(w, bid)
		sid := getRequestSID(r)
		if sid != "" {
			deleteSIDCookie(w)
			defaultUserStore.DeleteSessionUser(sid)
		}
		http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
	}
}

func PageHandler(loggedHandler http.HandlerFunc, unloggedHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user interface{}
		sid := getRequestSID(r)
		if sid != "" {
			user = defaultUserStore.GetSessionUser(sid)
			if user != nil {
				setSIDCookie(w, sid)
				//TODO save user data in context[r]
				loggedHandler(w, r)
				//TODO delete user data from context[r]
				return
			} else {
				deleteSIDCookie(w)
			}
		}

		bid := getRequestBID(r)
		if bid == "" {
			bid = GenerateID()
			user = defaultUserStore.CreateBrowserUser(bid)
		} else {
			user = defaultUserStore.GetBrowserUser(bid)
		}
		setBIDCookie(w, bid)
		//TODO save user data in context[r]
		unloggedHandler(w, r)
		//TODO delete user data from context[r]
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
