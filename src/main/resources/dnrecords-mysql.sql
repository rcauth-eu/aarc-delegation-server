/* 
  This assumes you already executed the script provided with standard OA4MP
  which creates the necessary user and database for you. 
*/

USE oa2server;

CREATE TABLE oa2server.trace_records (
  cn_hash             CHAR(64) PRIMARY KEY,
  sequence_nr         INTEGER,
  attribute_hash      CHAR(64),
  attribute_salt      CHAR(64),
  attribute_names     VARCHAR(255),
  first_seen          TIMESTAMP,
  last_seen	      TIMESTAMP
);

COMMIT;

GRANT ALL ON oa2server.trace_records TO 'oa4mp-server'@'localhost';

COMMIT;
