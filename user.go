package loginero

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"sync"
)

// UserManager does not introduce its own errors
// The returned errors can be only from UserStore
type UserManager interface {
	UserExists(uid string) (exists bool, err error)
	UpdatePassword(uid string, pass string) (updated bool, err error)
	CreateUser(user interface{}, pass string) (created bool, err error)
	CredsValid(uid string, pass string) (valid bool, err error)
	PasswordPolicy(pass string) error
	Hash(pass string) (hash string, err error)
	HashValid(hash string, pass string) (valid bool)
}

type UserStore interface {
	Get(uid string) (user interface{}, err error)
	Set(uid string, user interface{}) error
	Delete(uid string) error
}

// type related to particular UserManager implementation
type SimpleUser struct {
	UID      string
	Passhash string
}

type StandardUserManager struct {
	store UserStore
	mutex sync.Mutex
}

func (um *StandardUserManager) UserExists(uid string) (exists bool, err error) {
	u, err := um.store.Get(uid)
	exists = (u != nil)
	return exists, err
}

// return true if user was found and password was updated
func (um *StandardUserManager) UpdatePassword(uid string, pass string) (updated bool, err error) {
	u, err := um.store.Get(uid)
	if err == nil && u != nil {
		user := u.(*SimpleUser)
		hash, err := um.Hash(pass)
		if err == nil {
			user.Passhash = hash
			updated = true
		}
	}
	return updated, err
}

// return true if user does not exist yet (by uid) and the new one was saved
func (um *StandardUserManager) CreateUser(user interface{}, pass string) (created bool, err error) {
	uid := user.(*SimpleUser).UID
	um.mutex.Lock()
	defer um.mutex.Unlock()
	exists, err := um.UserExists(uid)
	if err == nil && !exists {
		hash, err := um.Hash(pass)
		if err == nil {
			user.(*SimpleUser).Passhash = hash
			err = um.store.Set(uid, user)
			if err == nil {
				created = true
			}
		}
	}
	return created, err
}

// return true if user exists and password matches
func (um *StandardUserManager) CredsValid(uid string, pass string) (valid bool, err error) {
	u, err := um.store.Get(uid)
	if err == nil && u != nil {
		user := u.(*SimpleUser)
		valid = um.HashValid(user.Passhash, pass)
		_ = fmt.Printf
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
	ExtractNewUser(r *http.Request) (uid string, pass string, user interface{}, err error)
	ExtractLogin(r *http.Request) (uid string, pass string, err error)
	ExtractTokenPass(r *http.Request) (token string, pass string, err error)
}

type StandardUserExtractor struct {
}

func (pe *StandardUserExtractor) ExtractNewUser(r *http.Request) (uid string, pass string, user interface{}, err error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if username != "" && pass1 != "" && pass1 == pass2 {
		return username, pass1, &SimpleUser{UID: username}, nil
	}
	return "", "", nil, errors.New("Wrong POST params")
}

func (pe *StandardUserExtractor) ExtractLogin(r *http.Request) (uid string, pass string, err error) {
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
	pass2 := r.FormValue("pass2")
	if token != "" && pass1 != "" && pass1 == pass2 {
		return token, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")
}
