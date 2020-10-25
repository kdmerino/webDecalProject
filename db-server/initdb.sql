-- We've decided to give you all the schema for all the databases

CREATE DATABASE auth;

USE auth;

CREATE TABLE users (
    username VARCHAR(20),
    email VARCHAR(320),
    hashedPassword TEXT,
    verified boolean,
    resetToken TEXT,
    verifiedToken TEXT,
    userId VARCHAR(128) PRIMARY KEY
);

CREATE DATABASE postsDB;

USE postsDB;

CREATE TABLE posts (
    content VARCHAR(255),
    postID VARCHAR(36) PRIMARY KEY,
    authorID VARCHAR(36),
    postTime DATETIME
);

CREATE DATABASE profiles;

USE profiles;

CREATE TABLE users (
    firstName VARCHAR(255),
    lastName VARCHAR(255),
    email VARCHAR(255),
    uuid VARCHAR(36) PRIMARY KEY
);


