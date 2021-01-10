This file contains information concerning the implementation of `api.go`. In `api.go` you are asked to fill out skeleton code for the functions `signup`, `signin`, `logout`, `verify`, `sendReset`, and `resetPassword`. Note that although the only file you are changing is `api.go` you should still look at other files as some functions or features may be partially implemented for you.

You will also need to fix `database.go`.

The table schema for this project is created as follows:

```
CREATE TABLE users (
    username VARCHAR(20),
    email VARCHAR(320),
    hashedPassword TEXT,
    verified boolean,
    resetToken TEXT,
    verifiedToken TEXT,
    userId VARCHAR(128) PRIMARY KEY
);
```

You do not need to fill out the skeleton code in the order below, but it is recommended to do so.

### `signup`

Users will sign up with a username, email, and password. We want to ensure that there are no duplicate accounts: if an email or username is already taken, then the request will fail and the relevant response is sent back.

SQL queries are made against the `users` table, and its schema is mentioned above. The docs for database library we are using in this project can be found here: https://golang.org/pkg/database/sql/

If the request succeeds, then we fill out the relevant fields in the user object before storing it. Note that we store the hash of the password rather than the password itself. (see "Hashing Passwords" section below.) Also note that sign up isn't complete in one step; we need to verify the user by sending them an email with the verification token.

We highly recommend that you finish this function first because it is the most involved. It will also be the function that will probably take you the longest.

### `verify`

This is the second part of the signup process. The user will receive an email containing the verification token. The user will use that email to "redeem" their token.

Note that when redeeming the token, the webserver has no idea from which location the user is redeeming the token from. As a consequence, we cannot match emails in order to determine which user has redeemed their verification token and must use some other means.

### `signin`

The process is similar to `signup` except for a few noticable differences:

1. The account already exists, so simply check if a database entry containing the username, email, and hashed password exists
2. Send an access token as a cookie instead of an email on success.

### `logout`

Delete the user's access token cookie. This cannot be done directly; clearing cookies is the responsibility of the browser. Instead, we delete cookies by setting its expiry time to before the current time.

### `resetPassword`

Resetting the password is similar to `verify` except instead of checking for a matching verification token, you must check for a matching password reset token. When the matching password token is found, the old password should be overwritten with the new password.

### `database.go`

The only change you need to do is to allow this microservice to communicate with the database. In order to do that, you need to open the database.

The information you need is included as a comment in `database.go`. We recommend looking at other the microservices' implementations to see how they communicate with the database. For further resources, these links may be helpful: 

 - https://tutorialedge.net/golang/golang-mysql-tutorial/

 - https://golang.org/pkg/database/sql/

### Hashing Passwords

Storing passwords in cleartext is a very bad idea because a database breach or a malacious database access leaks the passwords of your entire userbase. Thus, it is advised to hash the password using a cryptographic hash function. CS161 will go more in depth, but hashing the password means that even if an attacker manages full database access, it is infeasible to find the password of any account. This is because cryptographic hash functions are difficult to invert; that is, given an output, it is difficult to find any input which maps to that output without bruteforce.

In this project, these cryptographic hash functions are already implemented for you in the library `bcrypt`. The documentation for this library can be found here: https://godoc.org/golang.org/x/crypto/bcrypt.

In general, it is not feasible to invert the result of a hash function. Therefore, in order to determine whether or not a cleartext password matches a hash, one must hash the cleartext password and then check for equality.

`bcrypt` also includes a `cost` field in its hash function. This re-hashes the password `2^{cost}` times. For example, if `cost = 10` then the password will be hashed, and hashed, and hashed again 1024 times. A high cost function makes bruteforcing passwords more annoying, but also makes password verification slower. In this project, you can select any cost, but we recommend using the default cost `bcrypt.DefaultCost`.
