package loginero

import (
	"errors"
	mrand "math/rand"
	"net/http"
	"regexp"
)

var b62ascii = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62regexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

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

var sidName = "LO_SID"
var bidName = "LO_BID"
var dpe ParamExtractor

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

type ParamExtractor interface {
	ExtractNewUser(r *http.Request) (User, error)
	ExtractLogin(r *http.Request) (uid string, pass string, err error)
	ExtractPassReset(r *http.Request) (pass string, token string, err error)
	ExtractUsername(r *http.Request) (uid string, err error)
}

type StandardParamExtractor struct {
}

func (pe *StandardParamExtractor) ExtractNewUser(r *http.Request) (User, error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if username != "" && pass1 != "" && pass1 == pass2 {
		return &SimpleUser{UID: username, Password: pass1}, nil
	}
	return nil, errors.New("Wrong POST params")
}

func (pe *StandardParamExtractor) ExtractLogin(r *http.Request) (uid string, pass string, err error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	if username != "" && pass1 != "" {
		return username, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")

}

func (pe *StandardParamExtractor) ExtractPassReset(r *http.Request) (pass string, token string, err error) {
	token = r.FormValue("token")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if token != "" && pass1 != "" && pass1 == pass2 {
		return pass1, token, nil
	}
	return "", "", errors.New("Wrong POST params")
}

func (pe *StandardParamExtractor) ExtractUsername(r *http.Request) (uid string, err error) {
	username := r.FormValue("username")
	if username != "" {
		return username, nil
	}
	return "", errors.New("Wrong POST params")
}

////////////
