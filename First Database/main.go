package main

import (
	"database/sql"
	//"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var tpl *template.Template

var cookie_name = "my_database_board"

type Post struct {
	ID        uint64 `json:"ID"`
	UserID    uint64 `json:"user_ID"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}

type User struct {
	ID       uint64 `json:"ID"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./app.db")

	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS posts (
			ID INTEGER PRIMARY KEY AUTOINCREMENT,
			UserID INTEGER,
			Content TEXT NOT NULL,
			Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)

	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			ID INTEGER PRIMARY KEY AUTOINCREMENT,
			Username TEXT NOT NULL UNIQUE,
			Password TEXT NOT NULL		
		);	
	`)

	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
    		session_id TEXT PRIMARY KEY,
    		user_id INTEGER,
			FOREIGN KEY(user_id) REFERENCES users(ID) ON DELETE CASCADE
		);
	`)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Database initialized")
}

func sessionValid(r *http.Request) bool {
	cookie, err := r.Cookie(cookie_name)
	if err != nil {
		return false
	}

	rows, err := db.Query(`SELECT session_id FROM sessions WHERE session_id = ?`, cookie.Value)
	if err != nil {
		return false
	}

	defer rows.Close()
	return rows.Next()
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if sessionValid(r) {
		// logged in, return posts
		tpl.ExecuteTemplate(w, "index.html", nil)
	} else {
		// user not logged in, redirect to login
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		tpl.ExecuteTemplate(w, "signup.html", nil)
		return
	}

	var existingUsername string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUsername)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	if existingUsername != "" {
		// user already exists
		fmt.Println("Username is already in use")
		return
	} else {
		// add new user
		_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("User added successfully!")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		tpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	rows, err := db.Query(`SELECT username FROM users WHERE username = ? AND password = ?`, username, password)

	if err != nil {
		defer rows.Close()
		if rows.Next() {
			fmt.Println("User logged in")

			http.SetCookie(w, &http.Cookie{
				Name:  cookie_name,
				Value: "logged in",
				Path:  "/",
			})

			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	// problem logging in, try again
	tpl.ExecuteTemplate(w, "login.html", nil)
}

func main() {
	initDB()
	tpl, _ = template.ParseGlob("templates/*.html")

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server running on port 1234")
	log.Fatal(http.ListenAndServe(":1234", nil))
}
