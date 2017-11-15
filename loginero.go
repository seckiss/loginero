package loginero

import (
	"net/http"

	crand "crypto/rand"
	"math"
	"math/big"
	mrand "math/rand"
	"regexp"
)

var b62ascii = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62regexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
var defaultUserStore = RamUserStore{}
var sidName = "LO_SID"
var bidName = "LO_BID"

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

type SimpleUser struct {
	SID      string
	BID      string
	Username string
}

type RamUserStore struct {
}

func (store *RamUserStore) CreateUserCreds(r *http.Request, bid string) interface{} {
	return nil
}
func (store *RamUserStore) FindUserCreds(r *http.Request, bid string) interface{} {
	return nil
}
func (store *RamUserStore) ResetUserCreds(r *http.Request, bid string) interface{} {
	return nil
}
func (store *RamUserStore) GetSessionUser(sid string) interface{} {
	return nil
}
func (store *RamUserStore) GetBrowserUser(bid string) interface{} {
	return nil
}
func (store *RamUserStore) SaveSessionUser(sid string, user interface{}) {

}
func (store *RamUserStore) CreateBrowserUser(bid string) interface{} {
	return nil

}
func (store *RamUserStore) DeleteSessionUser(sid string) {

}

type UserStore interface {
	// use credentials from the request to create the new user object
	// store it in db and return it (without credentials)
	// return nil if user already exists (unique by username/email/id etc)
	// the bid argument may be used to link the anonymous BrowserUser (BIDuser)
	// with the newly created account/user
	CreateUserCreds(r *http.Request, bid string) interface{}
	// use credentials from the request to find user in the db
	// return it (without credentials) or nil if not found
	// the bid argument may be used to link the anonymous BrowserUser (BIDuser)
	// with the credential based logging in user
	FindUserCreds(r *http.Request, bid string) interface{}
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
			bid = generateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.FindUserCreds(r, bid)
		if user != nil {
			sid := generateID()
			setSIDCookie(w, sid)
			defaultUserStore.SaveSessionUser(sid, user)
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				defaultUserStore.DeleteSessionUser(sid)
			}
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
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
		user := defaultUserStore.CreateUserCreds(r, bid)
		if user != nil {
			sid := generateID()
			setSIDCookie(w, sid)
			defaultUserStore.SaveSessionUser(sid, user)
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				defaultUserStore.DeleteSessionUser(sid)
			}
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
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
			bid = generateID()
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
	if err != nil && validatedID(c.Value) {
		return c.Value
	}
	return ""
}

func getRequestSID(r *http.Request) string {
	c, err := r.Cookie(sidName)
	if err != nil && validatedID(c.Value) {
		return c.Value
	}
	return ""
}

// 16-chars of base62 gives about 95.3 bits of entropy
// This gives the space of about 10^10 generated ids with probability of collision = 10^-9 according to birthday paradox calcs
func generateID() string {
	var b = make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[i] = b62ascii[mrand.Intn(62)]
	}
	return string(b)
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
