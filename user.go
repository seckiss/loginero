package loginero

import (
	"errors"
	"net/http"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// UserManager does not introduce its own errors
// The returned errors can be only from UserStore
type UserManager interface {
	UserExists(uid string) (exists bool, err error)
	UpdatePassword(uid string, pass string) (updated bool, err error)
	CreateUser(uid string, pass string) (created bool, err error)
	CreateAnonUser(uid string) (err error)
	CredsValid(uid string, pass string) (valid bool, err error)
	PasswordPolicy(pass string) error
	Hash(pass string) (hash string, err error)
	HashValid(hash string, pass string) (valid bool)
}

type Creds struct {
	UID      string
	Passhash string
}

type StandardUserManager struct {
	Store TypeKeyValueStore
	mutex sync.Mutex
}

func (um *StandardUserManager) UserExists(uid string) (exists bool, err error) {
	c, err := um.Store.Get("uid2creds", uid)
	exists = (c != nil)
	return exists, err
}

// return true if user was found and password was updated
func (um *StandardUserManager) UpdatePassword(uid string, pass string) (updated bool, err error) {
	c, err := um.Store.Get("uid2creds", uid)
	if err == nil && c != nil {
		creds := c.(Creds)
		hash, err := um.Hash(pass)
		if err == nil {
			creds.Passhash = hash
			err = um.Store.Put("uid2creds", uid, creds)
			if err == nil {
				updated = true
			}
		}
	}
	return updated, err
}

// return true if user does not exist yet (by uid) and the new one was saved
func (um *StandardUserManager) CreateUser(uid string, pass string) (created bool, err error) {
	um.mutex.Lock()
	defer um.mutex.Unlock()
	exists, err := um.UserExists(uid)
	if err == nil && !exists {
		hash, err := um.Hash(pass)
		if err == nil {
			err = um.Store.Put("uid2creds", uid, Creds{UID: uid, Passhash: hash})
			if err == nil {
				created = true
			}
		}
	}
	return created, err
}

func (um *StandardUserManager) CreateAnonUser(uid string) (err error) {
	return um.Store.Put("anonuid", uid, uid)
}

// return true if user exists and password matches
func (um *StandardUserManager) CredsValid(uid string, pass string) (valid bool, err error) {
	c, err := um.Store.Get("uid2creds", uid)
	if err == nil && c != nil {
		creds := c.(Creds)
		valid = um.HashValid(creds.Passhash, pass)
	}
	return valid, err
}

func (um *StandardUserManager) PasswordPolicy(pass string) error {
	if len(pass) < 6 {
		return errors.New("Password must have at least 6 characters")
	}
	return nil
}

func (um *StandardUserManager) Hash(pass string) (hash string, err error) {
	err = um.PasswordPolicy(pass)
	if err == nil {
		bhash, err := bcrypt.GenerateFromPassword([]byte(pass), -1)
		if err == nil {
			hash = string(bhash)
		}
	}
	return hash, err
}

func (um *StandardUserManager) HashValid(hash string, pass string) (valid bool) {
	err := um.PasswordPolicy(pass)
	if err == nil {
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
		if err == nil {
			valid = true
		}
	}
	return valid
}

type UserExtractor interface {
	ExtractUserPass(r *http.Request) (uid string, pass string, err error)
	ExtractTokenPass(r *http.Request) (token string, pass string, err error)
}

type StandardUserExtractor struct {
}

func (pe *StandardUserExtractor) ExtractUserPass(r *http.Request) (uid string, pass string, err error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	if username != "" && pass1 != "" {
		return username, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")

}

func (pe *StandardUserExtractor) ExtractTokenPass(r *http.Request) (token string, pass string, err error) {
	token = r.FormValue("token")
	pass1 := r.FormValue("pass1")
	if token != "" && pass1 != "" {
		return token, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")
}
