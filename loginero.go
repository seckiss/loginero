package loginero

import (
	"net/http"

	crand "crypto/rand"
	mrand "math/rand"
	"regexp"
)

func SetOptions() {
	//TODO set BID and SID cookie template (Path, Secure, HttpOnly, MaxAge, etc)
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
	}
}

func getRequestBID(r *http.Request) string {

}

var b62ascii = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62regexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

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
	http.SetCookie(w, &http.Cookie{Name: "LO_BID", Value: bid, MaxAge: 500000000, Path: "/"})
}

func setSIDCookie(w http.ResponseWriter, sid string) {
	//TODO cookie should be cloned from options' SID cookie template
	//session cookie, no max-age
	http.SetCookie(w, &http.Cookie{Name: "LO_SID", Value: sid, Path: "/"})
}

func deleteBIDCookie(w http.ResponseWriter) {
	//TODO cookie should be cloned from options' BID cookie template
	http.SetCookie(w, &http.Cookie{Name: "LO_BID", Value: "", MaxAge: -1, Path: "/"})
}
func deleteSIDCookie(w http.ResponseWriter) {
	//TODO cookie should be cloned from options' SID cookie template
	http.SetCookie(w, &http.Cookie{Name: "LO_SID", Value: "", MaxAge: -1, Path: "/"})
}
