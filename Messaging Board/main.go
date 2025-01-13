package main

import (
	"database/sql"
	//"encoding/json"

	"html/template"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var tpl *template.Template

var cookie_name = "my_messaging_board"

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

func main() {

}
