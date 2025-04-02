-- CryptedConvo script

-- Drop the database if exists
DROP DATABASE IF EXISTS cryptedconvo;

-- Create the database
CREATE DATABASE cryptedconvo;

-- User the database
USE cryptedconvo;

-- Table 'users'
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id int(10) NOT NULL PRIMARY KEY,
    username VARCHAR(160) NOT NULL,
    salt TEXT(1024) NOT NULL,
    password_hash(1024) NOT NULL,
)
