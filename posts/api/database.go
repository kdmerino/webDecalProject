package api

import (
	"database/sql"
	"log"
	"time"

	//MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB() *sql.DB {

	log.Println("attempting connections")

	var err error
	
	// We've decided to give the connection string for the rest of the microservices
	DB, err = sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/postsDB?parseTime=true")

	_, err = DB.Query("SELECT * FROM posts")
	for err != nil {
		log.Println("couldnt connect, waiting 20 seconds before retrying")
		time.Sleep(20*time.Second)
		DB, err = sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/postsDB?parseTime=true")
	}

	return DB
}
