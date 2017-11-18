package loginero

import ()

var dum UserManager

type User interface {
	GetUID() string
	CheckPassword(pass string) bool
}
type SimpleUser struct {
	UID      string
	Password string
}

func (u *SimpleUser) GetUID() string {
	return u.UID
}

func (u *SimpleUser) CheckPassword(pass string) bool {
	return pass == u.Password
}

type UserManager interface {
	UserExists(uid string) (bool, error)
	UpdatePassword(uid string, pass string) (bool, error)
	CreateUser(u User, bid string) (bool, error)
	CredsValid(uid string, pass string, bid string) (bool, error)
}

type UserStore interface {
	Get(uid string) (User, error)
	Set(uid string, u User) error
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

func (um *StandardUserManager) CreateUser(u User, bid string) (bool, error) {
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
