DROP TABLE IF EXISTS subject_dn ; 

CREATE TABLE subject_dn (sha256 TEXT, content TEXT, dns_names_count INT, subject_c TEXT, subject_ou TEXT, subject_o TEXT, subject_cn TEXT) ;
CREATE TABLE dns_names (sha256 TEXT, content TEXT) ;
CREATE TABLE issuer_dn (sha256 TEXT, content TEXT, issuer_c TEXT, issuer_ou TEXT, issuer_o TEXT, issuer_cn TEXT) ;