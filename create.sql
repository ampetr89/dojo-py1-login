create database if not exists lang_app
;
use lang_app
;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id int primary key AUTO_INCREMENT,
  first_name varchar(100),
  last_name varchar(100),
  email varchar(100) not NULL,
  password_bcrypt varchar(255) not null,
  created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
)
;

