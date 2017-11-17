package main

import (
	"fmt"
	"log"
	"loginero"
	"net/http"
	"net/http/httputil"
)

func main() {

	/////////////////////////////////////////////////////////////////////////////
	// expected POST requests
	/////////////////////////////////////////////////////////////////////////////
	http.Handle("/login", loginero.LoginHandler("/page", "/loginform?failed=1"))
	http.Handle("/create", loginero.CreateAccountHandler("/page", "/createform?failed=1"))
	// after logout redirect to login form
	http.Handle("/logout", loginero.LogoutHandler("/loginform"))

	http.Handle("/reset", loginero.ResetPasswordHandler("/page", "/forgotform?failed=1"))
	http.Handle("/forgot", loginero.ForgotPasswordHandler(passtokenHandler))

	/////////////////////////////////////////////////////////////////////////////
	// expected GET requests
	/////////////////////////////////////////////////////////////////////////////
	http.Handle("/page", loginero.PageHandler(loggedHandler, unloggedHandler))
	http.Handle("/loginform", htmlHandler(`
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

	http.Handle("/createform", htmlHandler(`
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

	http.Handle("/forgotform", htmlHandler(`
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

	http.Handle("/resetform", htmlHandler(`
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

func DumpReq(r *http.Request) string {
	var dump string
	b, err := httputil.DumpRequest(r, true)
	if err != nil {
		dump = err.Error()
	} else {
		dump = string(b)
	}
	return dump
}

func htmlHandler(html string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}

func loggedHandler(w http.ResponseWriter, r *http.Request) {
	user := loginero.CurrentUser(r).(loginero.SimpleUser)
	htmlHandler("Hey "+user.Username+"! You are logged in")(w, r)
}

func unloggedHandler(w http.ResponseWriter, r *http.Request) {
	//here it should be anonymous user
	user := loginero.CurrentUser(r).(loginero.SimpleUser)
	htmlHandler("Logged out. Current user: "+user.Username)(w, r)
}

func passtokenHandler(w http.ResponseWriter, r *http.Request) {
	token := loginero.Token(r)
	if token == "" {
		htmlHandler("User not found")(w, r)
	} else {
		htmlHandler("In backend send token url to the user: http://127.0.0.1:8085/resetform?token="+token)(w, r)
	}
}
