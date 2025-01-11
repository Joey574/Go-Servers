package main

import (
	"html/template"
	"fmt"
	"net/http"
)

var cookie_name = "my_cookie"
var tpl *template.Template

func main() {
	tpl, _ = template.ParseGlob("templates/*.html")

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signupHandler)

	http.ListenAndServe(":1234", nil)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie(cookie_name)

	if (err == nil) {
		// cookie already present, user already logged in
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	username := r.FormValue("name")
	password := r.FormValue("password")

	if (username == "" || password == "") {
		// no username or password, just pass back html
		tpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie(cookie_name)

	if (err == nil) {
		// cookie already present, user already logged in
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: cookie_name,
		Value: "woohoo!",
		Path: "/",
	})
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie(cookie_name)

	if err != nil {
		fmt.Fprint(w, "Error with cookie")
		return
	}

	tpl.ExecuteTemplate(w, "index.html", nil)
}