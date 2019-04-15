/*
  This assumes you already executed the script provided with standard OA4MP
  which creates the necessary user and database for you.
*/

USE oa2server;

CREATE TABLE oa2server.trace_records (
  cn_hash             CHAR(44),
  sequence_nr         SMALLINT UNSIGNED,
  attribute_hash      CHAR(44),
  attribute_salt      CHAR(44),
  attribute_names     TEXT,
  first_seen          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_seen           TIMESTAMP,
  PRIMARY KEY (cn_hash, sequence_nr)
);

COMMIT;

GRANT ALL ON oa2server.trace_records TO 'oa4mp-server'@'localhost';

COMMIT;
