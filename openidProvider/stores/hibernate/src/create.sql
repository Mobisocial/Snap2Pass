grant all privileges on joid_test.* to 'test'@'localhost' \
         identified by 'password';
flush privileges;

drop table if exists Association, Nonce;

CREATE TABLE Association (
    id int(11) NOT NULL auto_increment,
    mode varchar(20) default NULL,
    handle varchar(255) default NULL,
    secret varchar(255) default NULL,
    issuedDate datetime default NULL,
    lifetime int(11) default NULL,
    associationType varchar(255) default NULL,
    PRIMARY KEY  (id)
);


CREATE TABLE Nonce (
   id int(11) NOT NULL auto_increment,
   nonce varchar(255) default NULL,
   checkedDate datetime default NULL,
   PRIMARY KEY  (id)
);