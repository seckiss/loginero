package loginero

import ()

var dum UserManager

type SimpleUser struct {
	UID      string
	Password string
}

// UserManager does not introduce its own errors
// The returned errors can be only from UserStore
type UserManager interface {
	UserExists(uid string) (bool, error)
	UpdatePassword(uid string, pass string) (bool, error)
	CreateUser(user interface{}, bid string) (bool, error)
	CredsValid(uid string, pass string, bid string) (bool, error)
}

type UserStore interface {
	Get(uid string) (user interface{}, err error)
	Set(uid string, user interface{}) error
}

type StandardUserManager struct {
	store UserStore
}

func (um *StandardUserManager) UserExists(uid string) (bool, error) {
	//TODO implement
	return false, nil
}

func (um *StandardUserManager) UpdatePassword(uid string, pass string) (bool, error) {
	//TODO implement
	return false, nil
}

func (um *StandardUserManager) CreateUser(user interface{}, bid string) (bool, error) {
	//TODO create user if uid does not exist
	//			newuser := SimpleUser{UID: username, Password: pass1}
	//			um.store.Set(username, &newuser)
	return false, nil
}

func (um *StandardUserManager) CredsValid(uid string, pass string, bid string) (bool, error) {
	// TODO uid and password check
	//			if user.CheckPassword(pass1) {
	return false, nil
}
