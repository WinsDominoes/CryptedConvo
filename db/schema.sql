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
    username VARCHAR(64) PRIMARY KEY,  -- Unique identifier
    salt BINARY(16) NOT NULL,          -- Exact storage for os.urandom(16)
    password_hash CHAR(64) NOT NULL 
)
