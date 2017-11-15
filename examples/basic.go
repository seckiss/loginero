package main

import (
	"fmt"
	"log"
	"loginero"
	"net/http"
	"net/http/httputil"
)

func main() {

	http.HandleFunc("/login", loginero.LoginHandler("/loginsuccess", "/loginfail"))
	ServeHTTP("127.0.0.1:8085", nil)
}

func ServeHTTP(hostport string, h http.Handler) {
	fmt.Printf("Starting http server: http://" + hostport)
	err := http.ListenAndServe(hostport, h)
	if err != nil {
		log.Fatal(err)
	}
}

func DumpReq(w http.ResponseWriter, r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		dump = []byte(err.Error())
	}
	fmt.Fprintf(w, "%s", dump)
}
