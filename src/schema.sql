DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS cert;


CREATE TABLE user (
    uid TEXT PRIMARY KEY NOT NULL,
    lastname TEXT NOT NULL,
    firstname TEXT NOT NULL,
    email TEXT NOT NULL,
    passwd TEXT NOT NULL
);

CREATE TABLE cert (
    issued_time TEXT,
    revoked_time TEXT UNIQUE,
    uid TEXT NOT NULL,
    key TEXT NOT NULL,
    is_activated INT NOT NULL,
    PRIMARY KEY (issued_time, uid),
    FOREIGN KEY (uid) REFERENCES user(uid)
);


INSERT INTO user VALUES
('eliz', 'Elizabeth', 'Welter', 'eliz@security.com', '1a9bb892d2beec91beaf415025f5e109bad6081f'),
('seger', 'Seger', 'George', 'seger@kaist-is561.com', '9b08b0357d2f1d34ecf42dfd9bc5001733fca132'),
('kung', 'Kung', 'Qiang', 'kung@hello.kr', '647f8e8c95e4cfc7254cf3dc7bb4f79b97d12712');
