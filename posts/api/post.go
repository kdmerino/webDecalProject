package api

import "time"

type Post struct {
	PostBody  string    `json:"postBody"`
	PostID   string    `json:"postID"`
	AuthorID string    `json:"AuthorID"`
	PostTime time.Time `json:"postTime"`
	PostAuthor string `json:"postAuthor"`
}
