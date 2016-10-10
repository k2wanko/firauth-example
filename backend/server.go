package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"

	"github.com/gorilla/mux"
	auth "github.com/k2wanko/firebase-auth"
	"github.com/mjibson/goon"

	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"

	cascadestore "github.com/k2wanko/go-appengine-sessioncascade"
)

const sessionName = "session"

var (
	store *cascadestore.CascadeStore
)

type (
	Token struct {
		UserID      string `datastore:"-" goon:"id"`
		TeamID      string
		TeamName    string
		Scope       string
		AccessToken string
	}
)

func (t *Token) FirToken(c context.Context) (string, error) {
	return auth.CreateCustomToken(c, t.UserID, map[string]interface{}{
		"team_id": t.TeamID,
	})
}

func init() {
	r := mux.NewRouter()
	r.HandleFunc("/auth/handler", handleAuthHandler).Methods("GET")
	r.HandleFunc("/auth", handleAuth).Methods("GET")
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/slack/{method}", handleAPISlack).Methods("POST")
	http.Handle("/", r)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	s, err := store.Get(r, sessionName)
	if err != datastore.ErrNoSuchEntity {
		r.Header.Del("Cookie")
		s, err = store.Get(r, sessionName)
		if err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	}
	s.Values["state"] = state
	s.Save(r, w)

	if oauthConf.RedirectURL == "" {
		host := "localhost:8080"
		scheme := "http"
		if !isDevServer() {
			ctx := newContext(r)
			scheme = "https"
			host = fmt.Sprintf("%s.appspot.com", appengine.AppID(ctx))
		}
		oauthConf.RedirectURL = fmt.Sprintf("%s://%s/auth/handler", scheme, host)
	}

	url := oauthConf.AuthCodeURL(state)

	http.Redirect(w, r, url, 302)
}

func handleAuthHandler(w http.ResponseWriter, r *http.Request) {
	s, err := store.Get(r, sessionName)
	if err != nil {
		panic(err)
	}

	if r.URL.Query().Get("state") != s.Values["state"] {
		http.Error(w, "Bad request: state", 400)
		return
	}

	ctx := newContext(r)
	tok, err := oauthConf.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		panic(err)
	}

	t := &Token{
		AccessToken: tok.AccessToken,
		UserID:      tok.Extra("user_id").(string),
		TeamID:      tok.Extra("team_id").(string),
		TeamName:    tok.Extra("team_name").(string),
		Scope:       tok.Extra("scope").(string),
	}

	g := goon.FromContext(ctx)
	_, err = g.Put(t)
	if err != nil {
		panic(err)
	}

	firTok, err := t.FirToken(ctx)
	if err != nil {
		panic(err)
	}

	logf(ctx, "token: %s", firTok)

	w.Header().Add("content-type", "text/html")
	w.WriteHeader(200)
	tpl.Execute(w, firTok)
}

const handleHTML = `
<!DOCTYPE html>
<title>Firebase Auth Example</title>
<meta charset="utf-8">
<div id="token" data-token="{{.}}"></div>
<script>
window.onload = () => {
	const token = document.getElementById("token").dataset.token
	opener.postMessage({token: token}, location.origin)
	window.close()
}
!(function(){
	opener.postMessage("hi", location.origin)
})
</script>
`

var tpl = template.Must(template.New("firauth").Parse(handleHTML))

const bearerStr = "Bearer "

func handleAPISlack(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r)
	bearer := r.Header.Get("Authorization")
	logf(ctx, "bearer: %s", bearer)
	if bearer == "" || len(bearerStr) >= len(bearer) {
		http.Error(w, "Invalid Token", 400)
		return
	}
	bearer = bearer[len(bearerStr):]

	t, err := auth.VerifyIDToken(ctx, bearer)
	if err != nil {
		logf(ctx, "invliad token %v", err)
		http.Error(w, "Invalid Token", 400)
		return
	}
	claims := t.Claims.(*auth.FirebaseClaims)
	tok := &Token{UserID: claims.UserID()}
	g := goon.FromContext(ctx)
	if err := g.Get(tok); err != nil {
		panic(err)
	}

	v := mux.Vars(r)
	method := v["method"]
	if method == "" {
		http.Error(w, "No method", 400)
		return
	}

	q := r.URL.Query()
	q.Add("token", tok.AccessToken)
	q.Add("pretty", "1")

	req, err := http.NewRequest("POST", fmt.Sprintf("https://slack.com/api/%s?%s", method, q.Encode()), nil)
	if err != nil {
		panic(err)
	}
	resp, err := ctxhttp.Do(ctx, urlfetch.Client(ctx), req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func isDevServer() bool {
	return os.Getenv("RUN_WITH_DEVAPPSERVER") != ""
}

func newContext(r *http.Request) context.Context {
	return appengine.NewContext(r)
}

func cacheControl(w http.ResponseWriter, t time.Duration) {
	w.Header().Add("cache-control", fmt.Sprintf("max-age=%f", t.Seconds()))
}

func logf(c context.Context, format string, args ...interface{}) {
	log.Infof(c, format, args...)
}

func errorf(c context.Context, format string, args ...interface{}) {
	log.Errorf(c, format, args...)
}
