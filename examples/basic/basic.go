package main

import (
	"../../boltstore"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	webpush "github.com/sherclockholmes/webpush-go"
	"html"
	"log"
	"loginero"
	"net/http"
	"time"
)

func p(fs string, args ...interface{}) {
	log.Printf(fs+"\n", args...)
}

func main() {

	gob.Register(loginero.SimpleUser{})
	gob.Register(loginero.Session{})
	gob.Register([]loginero.Session{})
	gob.Register(webpush.Subscription{})

	var commonStore loginero.KeyValueStore
	var err error

	commonStore, err = boltstore.Open("/tmp/basicloginero.db")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			commonStore.(*boltstore.BoltStore).DumpStore()
			time.Sleep(10 * time.Second)
		}
	}()

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

	// push subscription
	http.HandleFunc("/api/v2/pushsubscription", loginero.PageController(apiPushsubscriptionHandler))

	/////////////////////////////////////////////////////////////////////////////
	// expected GET requests
	/////////////////////////////////////////////////////////////////////////////
	http.Handle("/service-worker.js", handlerFromJs(serviceWorker))
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

func handlerFromJs(js string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(js))
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
	handlerFromHtml("Current user: "+sess.UID+"<br/>"+html.EscapeString(s)+"<br/><br/><hr/><br/>"+webpushScript)(w, r)
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

func apiPushsubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	var sub = webpush.Subscription{}
	err := decoder.Decode(&sub)
	if err != nil {
		p("json decode error: %v", err)
		w.WriteHeader(400)
		return
	}
	p("decoded webpush.Subscription: %+v", sub)

	sess, err := loginero.CurrentSession(r)
	if err != nil {
		p("CurrentSession error: %v", err)
	}

	err = loginero.SetDeviceForSession(sess.ID, sub)

	if err != nil {
		p("WebPush save error: %v", err)
	}
}

var webpushScript = `
<script>
  // Converts the URL-safe base64 encoded |base64UrlData| to an Uint8Array buffer.
  function base64UrlToUint8Array(base64UrlData) {
    var padding = '='.repeat((4 - base64UrlData.length % 4) % 4);
    var base64 = (base64UrlData + padding).replace(/\-/g, '+').replace(/_/g, '/');

    var rawData = window.atob(base64);
    var buffer = new Uint8Array(rawData.length);

    for (var i = 0; i < rawData.length; ++i) {
      buffer[i] = rawData.charCodeAt(i);
    }
    return buffer;
  }

  var vapidPublicKey = 'BEPNeV1ahQ4B_a9Y21nUygVWayOyZzxgVIpN79lGS7mLp5cClnoqQchuCgu0T7HezKVg0WF5OfK1Bmt9WgTcqRw';

  function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('./service-worker.js')
      .then(function() {
        console.log('registerServiceWorker completed');
        //_pushClient.subscribeDevice();
      })
      .catch((err) => {
        console.log('Unable to Register Service Worker');
        console.error(err);
      });
    } else {
      console.log('Service Worker Not Supported');
    }
  }

  // return object with error messages, or empty object if all supported
  function browserSupport() {
        if (!('serviceWorker' in navigator)) {
          return {code: 'SW', err: 'Service worker not available on this browser'};
        }
        if (!('PushManager' in window)) {
          return {code: 'PM', err: 'PushManager not available on this browser'};
        }
        if (!('showNotification' in ServiceWorkerRegistration.prototype)) {
          return {code: 'SN', err: 'Showing Notifications from a service worker is not available on this browser'};
        }
        return {};
  }


  var notificationPermission = '';

  if (window) {
    window.onload = function() {
      registerServiceWorker();
    };
    // So this should be called when setting up an alerts/notifications
    document.documentElement.addEventListener('click', function() {
      return navigator.serviceWorker.ready.then((swRegistration) => {
        Notification.requestPermission().then((perm) => {
          notificationPermission = perm;
          if (perm == 'granted') {
            var pushOptions = {userVisibleOnly: true, applicationServerKey: base64UrlToUint8Array(vapidPublicKey)};
            swRegistration.pushManager.subscribe(pushOptions).then(
              (subscription) => {
                var s = JSON.stringify(subscription, null, 2);
                fetch('/api/v2/pushsubscription', {method: 'post', body: s}).then(function(response) {
                    console.log('subscription posted: %o', s);
                    console.log('pushsubscription response: %o', response);
                  });
              },
              (err) => { console.log('Subscription error: %o', err)}
            );
          } else {
            console.log('Notification permission NOT granted');
          }
        });
      });
    });
  }
</script>
`

var serviceWorker = `
'use strict';

/* eslint-env browser, serviceworker */

//importScripts('./scripts/libs/idb-keyval.js');

self.addEventListener('push', function(event) {
  console.log('Received push');
  let notificationTitle = 'Hello';
  const notificationOptions = {
    body: 'Thanks for sending this push msg.',
    icon: 'img/face72.png',
    //badge: 'img/face72.png',
    image: 'img/scene2.jpg',
    tag: 'simple-push-demo-notification',
    data: {
      url: 'https://fruho.com',
    },
  };



  if (event.data) {
    const dataText = event.data.text();
    notificationTitle = 'Received Payload';
    notificationOptions.body = 'Push data: ${dataText}';
  }

  event.waitUntil(
    Promise.all([
      self.registration.showNotification(
        notificationTitle, notificationOptions),
    ])
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();

  let clickResponsePromise = Promise.resolve();
  if (event.notification.data && event.notification.data.url) {
    //clickResponsePromise = clients.openWindow(event.notification.data.url);
  }

  event.waitUntil(
    Promise.all([
      clickResponsePromise,
    ])
  );
});

self.addEventListener('notificationclose', function(event) {
  event.waitUntil(
    Promise.all([
    ])
  );
});

`
