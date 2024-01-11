CREATE
DATABASE spring_security_basic;

CREATE TABLE users
(
    id       INT         NOT NULL AUTO_INCREMENT,
    username VARCHAR(45) NOT NULL,
    password VARCHAR(45) NOT NULL,
    enabled  INT         NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE authorities
(
    id        INT         NOT NULL AUTO_INCREMENT,
    username  VARCHAR(45) NOT NULL,
    authority VARCHAR(45) NOT NULL,
    PRIMARY KEY (id)
);

INSERT
IGNORE INTO users VALUES(NULL, "happy","12345","1");
INSERT
IGNORE INTO authorities VALUES(NULL, "happy", "write");

CREATE TABLE Customer
(
    id    INT          NOT NULL AUTO_INCREMENT,
    email VARCHAR(45)  NOT NULL,
    pwd   VARCHAR(200) NOT NULL,
    role  VARCHAR(45)  NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO Customer(email, pwd, role)
VALUES ("iffat@gmail.com", "54321", "admin");