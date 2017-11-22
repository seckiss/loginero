package main

import (
	"../../boltstore"
	"encoding/gob"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"html"
	"log"
	"loginero"
	"net/http"
)

func main() {

	gob.Register(loginero.SimpleUser{})
	gob.Register(loginero.Session{})
	gob.Register([]loginero.Session{})

	var commonStore loginero.KeyValueStore
	var err error

	commonStore, err = boltstore.Open("/tmp/basicloginero.db")
	if err != nil {
		panic(err)
	}

	def := loginero.DefaultInstance
	def.DeviceMan = &loginero.StandardDeviceManager{
		Store: commonStore,
	}
	def.SessMan = &loginero.StandardSessionManager{
		Store: commonStore,
	}
	def.UserMan = &loginero.StandardUserManager{
		Store: commonStore,
	}
	/////////////////////////////////////////////////////////////////////////////
	// expected POST requests
	/////////////////////////////////////////////////////////////////////////////
	http.Handle("/login", loginero.LoginController(loginHandler))
	http.Handle("/create", loginero.CreateAccountController(createAccountHandler))
	http.Handle("/logout", loginero.LogoutController(logoutHandler))
	//http.Handle("/reset", loginero.ResetPasswordController("/page", "/forgotform?failed=1"))
	http.Handle("/reset", loginero.ResetPasswordController(resetHandler))

	http.HandleFunc("/forgot", passtokenHandler)

	/////////////////////////////////////////////////////////////////////////////
	// expected GET requests
	/////////////////////////////////////////////////////////////////////////////
	http.Handle("/page", loginero.PageController(pageHandler))
	http.Handle("/loginform", handlerFromHtml(`
    <form action="/login" method="POST">
      <label style="color: red;"></label>
      <div>Username: <input type="text" name="username"></input></div>
      <div>Password: <input type="password" name="pass1"></input></div>
      <div><input type="submit" value="Log in"></input></div>
    </form>
    <script>
      let params = (new URL(location)).searchParams;
      if (params.get('failed') == '1') {
        document.querySelector('label').textContent = 'Login failed'
      }
    </script>
  `))

	http.Handle("/createform", handlerFromHtml(`
    <form action="/create" method="POST">
      <label style="color: red;"></label>
      <div>Username: <input type="text" name="username"></input></div>
      <div>Password: <input type="password" name="pass1"></input></div>
      <div>Repeat: <input type="password" name="pass2"></input></div>
      <div><input type="submit" value="Create Account"></input></div>
    </form>
    <script>
      let params = (new URL(location)).searchParams;
      if (params.get('failed') == '1') {
        document.querySelector('label').textContent = 'Account could not be created'
      }
    </script>
  `))

	http.Handle("/forgotform", handlerFromHtml(`
    <form action="/forgot" method="POST">
      <label style="color: red;"></label>
      <div>Username: <input type="text" name="username"></input></div>
      <div><input type="submit" value="Remind Password"></input></div>
    </form>
    <script>
      let params = (new URL(location)).searchParams;
      if (params.get('failed') == '1') {
        document.querySelector('label').textContent = 'Password reset failed'
      }
    </script>
  `))

	http.Handle("/resetform", handlerFromHtml(`
    <form action="/reset" method="POST">
      <label style="color: red;"></label>
			<input type="hidden" name="token"></input>
      <div>Password: <input type="password" name="pass1"></input></div>
      <div>Repeat: <input type="password" name="pass2"></input></div>
      <div><input type="submit" value="Reset Password"></input></div>
    </form>
    <script>
      let params = (new URL(location)).searchParams;
			document.querySelector('input[type="hidden"]').value = params.get('token');
    </script>
  `))

	ServeHTTP("127.0.0.1:8085", nil)
}

func ServeHTTP(hostport string, h http.Handler) {
	fmt.Printf("Starting http server: http://%s\n", hostport)
	err := http.ListenAndServe(hostport, h)
	if err != nil {
		log.Fatal(err)
	}
}

func handlerFromHtml(html string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	sess, err := loginero.CurrentSession(r)
	if err != nil {
		fmt.Printf("loginHandler err=%v\n", err)
	}
	if sess.Anon {
		// unlogged
		http.Redirect(w, r, "/loginform?failed=1", http.StatusSeeOther)
	} else {
		// logged
		http.Redirect(w, r, "/page", http.StatusSeeOther)
	}
}

func createAccountHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := loginero.CurrentSession(r)
	if sess.Anon {
		// unlogged, create account failed for client reasons
		http.Redirect(w, r, "/createform?failed=1", http.StatusSeeOther)
	} else {
		// logged, account created
		http.Redirect(w, r, "/page", http.StatusSeeOther)
	}
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := loginero.CurrentSession(r)
	if sess.Anon {
		// unlogged, reset password failed
		http.Redirect(w, r, "/forgotform?failed=1", http.StatusSeeOther)
	} else {
		// logged, password reset
		http.Redirect(w, r, "/page", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	//sess, _ := loginero.CurrentSession(r)
	http.Redirect(w, r, "/loginform", http.StatusSeeOther)
}

func pageHandler(w http.ResponseWriter, r *http.Request) {
	sess, err := loginero.CurrentSession(r)
	if err != nil {
		fmt.Printf("pageHandler 1 err=%v\n", err)
	}

	sessions, err := loginero.DefaultInstance.SessMan.UserGetSessions(sess.UID)
	if err != nil {
		fmt.Printf("pageHandler 2 err=%v\n", err)
	}

	s := spew.Sdump(sessions)
	handlerFromHtml("Current user: "+sess.UID+"<br/>"+html.EscapeString(s))(w, r)
}

func passtokenHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.FormValue("username")
	token, _ := loginero.UserToken(uid)
	if token != "" {
		handlerFromHtml("In backend send token url to the user: http://127.0.0.1:8085/resetform?token="+token)(w, r)
	} else {
		handlerFromHtml("User not found")(w, r)
	}
}
