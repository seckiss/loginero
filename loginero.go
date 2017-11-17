package loginero

import (
	"net/http"

	crand "crypto/rand"
	"fmt"
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
var contextUser = make(map[*http.Request]interface{})
var contextUserMutex sync.RWMutex
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

func CurrentUser(r *http.Request) interface{} {
	contextUserMutex.RLock()
	defer contextUserMutex.RUnlock()
	return contextUser[r]
}

func Token(r *http.Request) string {
	contextTokenMutex.RLock()
	defer contextTokenMutex.RUnlock()
	return contextToken[r]
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

func (store *RamUserStore) BindToken(r *http.Request, token string, bid string) interface{} {
	username := r.FormValue("username")
	if username != "" {
		store.UidMutex.RLock()
		defer store.UidMutex.RUnlock()
		if user, pres := store.Uid2User[username]; pres {
			store.ResetMutex.Lock()
			defer store.ResetMutex.Unlock()
			store.ResetToken2User[token] = user
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
	fmt.Printf("r=%+v\n", r)
	fmt.Println("1111")
	if pass1 == pass2 {
		fmt.Println("222")
		store.ResetMutex.Lock()
		defer store.ResetMutex.Unlock()
		user, pres := store.ResetToken2User[token]
		fmt.Printf("rtu=%+v\n", store.ResetToken2User)
		if pres {
			// it's one-time user token, so delete if found
			delete(store.ResetToken2User, token)
			updated := user.(SimpleUser)
			updated.Password = pass1

			// note that in case of RamUserStore we could operate on *User and not User
			// in this way we could avoid updating Uid2User map (single instance of object in RAM and maps could keep only references)
			// but in general case (disk/db implementation) it would not work
			// so we do this step here as well to make the example complete

			store.UidMutex.Lock()
			defer store.UidMutex.Unlock()
			store.Uid2User[updated.Username] = updated

			// note that we cannot update user records in Sid2User
			// Bid2User does not matter because it does not contain passwords
			return updated
		}
	}
	return nil
}

func (store *RamUserStore) GetSessionUser(sid string) interface{} {
	store.SidMutex.RLock()
	defer store.SidMutex.RUnlock()
	user, pres := store.Sid2User[sid]
	if pres {
		return user
	}
	return nil
}

func (store *RamUserStore) GetBrowserUser(bid string) interface{} {
	store.BidMutex.RLock()
	defer store.BidMutex.RUnlock()
	user, pres := store.Bid2User[bid]
	if pres {
		return user
	}
	return nil
}

func (store *RamUserStore) SaveSessionUser(sid string, user interface{}) {
	store.SidMutex.Lock()
	defer store.SidMutex.Unlock()
	store.Sid2User[sid] = user
}

func (store *RamUserStore) CreateBrowserUser(bid string) interface{} {
	// For anonymous user we use the same struct as for logged user
	// This is an implementation detail (other implementations may return a different struct)
	user := SimpleUser{Username: bid, Password: ""}
	store.BidMutex.Lock()
	defer store.BidMutex.Unlock()
	store.Bid2User[bid] = user
	return user
}

func (store *RamUserStore) DeleteSessionUser(sid string) {
	store.SidMutex.Lock()
	defer store.SidMutex.Unlock()
	delete(store.Sid2User, sid)
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
	// and bind it to the token
	// return bound user or nil if user not found
	BindToken(r *http.Request, token string, bid string) interface{}
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
			bid = generateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.CheckUserCreds(r, bid)
		if user != nil {
			sid := generateID()
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
			bid = generateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.CreateUserCreds(r, bid)
		if user != nil {
			sid := generateID()
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
			bid = generateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.ResetUserCreds(r, bid)
		if user != nil {
			sid := generateID()
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
// Bound token is passed in context
// The token is empty string if user not found
func ForgotPasswordHandler(passtokenHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)

		token := generateID()
		user := defaultUserStore.BindToken(r, token, bid)
		if user == nil {
			//reset token to empty if user not found
			token = ""
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

				//save user data in context
				contextUserMutex.Lock()
				contextUser[r] = user
				contextUserMutex.Unlock()

				loggedHandler(w, r)

				//delete user data from context
				contextUserMutex.Lock()
				delete(contextUser, r)
				contextUserMutex.Unlock()

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
			if user == nil {
				bid = generateID()
				user = defaultUserStore.CreateBrowserUser(bid)
			}
		}
		setBIDCookie(w, bid)

		//save user data in context
		contextUserMutex.Lock()
		contextUser[r] = user
		contextUserMutex.Unlock()

		fmt.Printf("user=%+v\n", user)

		unloggedHandler(w, r)

		//delete user data from context
		contextUserMutex.Lock()
		delete(contextUser, r)
		contextUserMutex.Unlock()
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
