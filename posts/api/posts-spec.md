This file contains information concerning the implementation of `api.go`. In `api.go` you are asked to fill out skeleton code for the functions `getUUID`, `getPosts`, `createPost`, `deletePost`, and `getFeed`. Note that although the only file you are changing is `api.go` you should still look at other files as some functions or features may be partially implemented for you.

You do not need to fill out the skeleton code in the order below, but it is recommended to do so.

This part of the project will interact with the `posts` database which is created with the following schema:

```
CREATE TABLE posts (
    content VARCHAR(255),
    postID VARCHAR(36) PRIMARY KEY,
    authorID VARCHAR(36),
    postTime DATETIME
);
```

### `getUUID`

The skeleton code is already functional, assuming that no errors arise. If an error occurs, return an error response using `http.Error` and log the error.

### `createPost`

Insert the post into the database and check for an error. If an error occurs, return an `http.Error` response and log the error.

### `deletePost`

Check if the given post exists. If it does, then check if the person trying to delete the post is also the author of the post. If they are, then delete the post. If an error occurs at any stage of this process, return an `http.Error` response and log the error.

If you are unsure how to perform the database calls, check the `auth-service/api/api.go` functions to see how it was done there.

### `getPosts`

This function gets 25 posts from a specific user starting from some starting post index, sorted by post time in ascending order. If the user does not have 25 posts from that starting post index, then the function instead returns as many posts as possible. Note that we are getting posts from a starting index rather than a specific post time or post ID. If `startingIndex == 0` then the function will return the first 25 posts the user has ever made. If `startingIndex == 25` and the user has only made 29 posts, then the function will return the latest 5 posts.

You will first implement some error checking similar to `getUUID`. Then, you will make an SQL database query and retrieve the posts. The database schema is noted above. We will then put every row of the returned query into a `Post` instance. The details of a `Post` object can be seen in `post.go`. Finally, we add all of those `Post` instances into an array and return the array of `Post`s.

### `getFeed`

This function is identical to `getPosts` except instead of getting 25 posts from a specific user, you are getting 25 posts from anyone except that specific user.

### `jwt.go`

You do not need to make any changes to this file. This file provides you with the `AuthClaims` object (an extended class of `jwt.StandardClaims`) and the helper function `ValidateToken` which returns a map. In the context of this project, this map can be implicitly casted as an `AuthClaims` object.

You may also have noticed that we are using the hardcoded secret key `"my_secret_key"` for JWT encryption. This is bad and insecure, but for now you can ignore this. We will implement a fix later.

For more information, feel free to parse the `jwt-go` docs: https://godoc.org/github.com/dgrijalva/jwt-go
