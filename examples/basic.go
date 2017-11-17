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
	http.Handle("/createaccount", loginero.CreateAccountHandler("/page", "/createaccountform?failed=1"))
	// after logout redirect to login form
	http.Handle("/logout", loginero.LogoutHandler("/loginform"))
	http.Handle("/resetpassword", loginero.ResetPasswordHandler("/page", "/resetpasswordform"))

	/////////////////////////////////////////////////////////////////////////////
	// expected GET requests
	/////////////////////////////////////////////////////////////////////////////
	http.Handle("/page", loginero.PageHandler(loggedHandler, unloggedHandler))
	http.Handle("/loginform", htmlHandler(`
    <form action="/login" method="POST">
      <label style="color: red;"></label>
      <div>Username: <input type="text" name="username"></input></div>
      <div>Password: <input type="password" name="pass1"></input></div>
      <div>Repeat: <input type="password" name="pass2"></input></div>
      <div><input type="submit" value="Log in"></input></div>
    </form>
    <script>
      let params = (new URL(location)).searchParams;
      if (params.get('failed') == '1') {
        document.querySelector('label').textContent = 'Login failed'
      }
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
}

func unloggedHandler(w http.ResponseWriter, r *http.Request) {
}
