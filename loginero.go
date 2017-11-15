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

type RamUserStore struct {
}

func (store *RamUserStore) CreateUserCreds(r *http.Request) interface{} {
	return nil
}
func (store *RamUserStore) FindUserCreds(r *http.Request) interface{} {
	return nil
}
func (store *RamUserStore) GetSIDUser(sid string) interface{} {
	return nil
}
func (store *RamUserStore) GetBIDUser(bid string) interface{} {
	return nil
}
func (store *RamUserStore) SaveSIDUser(sid string, user interface{}) {

}
func (store *RamUserStore) SaveBIDUser(bid string, user interface{}) {

}
func (store *RamUserStore) DeleteSIDUser(sid string) {

}
func (store *RamUserStore) DeleteBIDUser(bid string) {

}

type UserStore interface {
	// use credentials from the request to create the new user object
	// store it in db and return it (without credentials)
	// return nil if user already exists (unique by username/email/id etc)
	CreateUserCreds(r *http.Request) interface{}
	// use credentials from the request to find user in the db
	// return it (without credentials) or nil if not found
	FindUserCreds(r *http.Request) interface{}
	GetSIDUser(sid string) interface{}
	GetBIDUser(bid string) interface{}
	SaveSIDUser(sid string, user interface{})
	SaveBIDUser(bid string, user interface{})
	DeleteSIDUser(sid string)
	DeleteBIDUser(bid string)
}

func LoginHandler(redirectSuccess string, redirectFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bid := getRequestBID(r)
		if bid == "" {
			bid = generateID()
		}
		setBIDCookie(w, bid)
		user := defaultUserStore.FindUserCreds(r)
		if user != nil {
			sid := generateID()
			setSIDCookie(w, sid)
			defaultUserStore.SaveSIDUser(sid, user)
			http.Redirect(w, r, redirectSuccess, http.StatusSeeOther)
		} else {
			sid := getRequestSID(r)
			if sid != "" {
				deleteSIDCookie(w)
				defaultUserStore.DeleteSIDUser(sid)
			}
			http.Redirect(w, r, redirectFail, http.StatusSeeOther)
		}
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

func validatedID(rid string) bool {
	return len(rid) == 16 && b62regexp.MatchString(rid)
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
