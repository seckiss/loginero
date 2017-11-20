package loginero

import (
	"errors"
	"net/http"
)

// UserManager does not introduce its own errors
// The returned errors can be only from UserStore
type UserManager interface {
	UserExists(uid string) (exists bool, err error)
	UpdatePassword(uid string, pass string) (updated bool, err error)
	CreateUser(user interface{}) (created bool, err error)
	CredsValid(uid string, pass string) (valid bool, err error)
}

type UserStore interface {
	Get(uid string) (user interface{}, err error)
	Set(uid string, user interface{}) error
	Delete(uid string) error
}

// type related to particular UserManager implementation
type SimpleUser struct {
	UID      string
	Password string
}

type StandardUserManager struct {
	store UserStore
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
		user.Password = pass
		updated = true
	}
	return updated, err
}

// return true if user does not exist yet (by uid) and the new one was saved
func (um *StandardUserManager) CreateUser(user interface{}) (created bool, err error) {
	uid := user.(*SimpleUser).UID
	//TODO sync

	exists, err := um.UserExists(uid)
	if err == nil && !exists {
		err = um.store.Set(uid, user)
		if err == nil {
			created = true
		}
	}
	return created, err
}

func (um *StandardUserManager) CredsValid(uid string, pass string) (valid bool, err error) {
	u, err := um.store.Get(uid)
	if err == nil && u != nil {
		user := u.(*SimpleUser)
		if user.Password == pass {
			valid = true
		}
	}
	return valid, err
}

type ParamExtractor interface {
	ExtractNewUser(r *http.Request) (uid string, user interface{}, err error)
	ExtractLogin(r *http.Request) (uid string, pass string, err error)
	ExtractTokenPass(r *http.Request) (token string, pass string, err error)
}

type StandardParamExtractor struct {
}

func (pe *StandardParamExtractor) ExtractNewUser(r *http.Request) (uid string, user interface{}, err error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if username != "" && pass1 != "" && pass1 == pass2 {
		return username, &SimpleUser{UID: username, Password: pass1}, nil
	}
	return "", nil, errors.New("Wrong POST params")
}

func (pe *StandardParamExtractor) ExtractLogin(r *http.Request) (uid string, pass string, err error) {
	username := r.FormValue("username")
	pass1 := r.FormValue("pass1")
	if username != "" && pass1 != "" {
		return username, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")

}

func (pe *StandardParamExtractor) ExtractTokenPass(r *http.Request) (token string, pass string, err error) {
	token = r.FormValue("token")
	pass1 := r.FormValue("pass1")
	pass2 := r.FormValue("pass2")
	if token != "" && pass1 != "" && pass1 == pass2 {
		return token, pass1, nil
	}
	return "", "", errors.New("Wrong POST params")
}
