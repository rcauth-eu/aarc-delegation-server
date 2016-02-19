/* 
  This assumes you already executed the script provided with standard OA4MP
  which creates the necessary user and database for you. 
*/

USE oauth2;

CREATE TABLE oauth2.dn_records (
  dn_hash             CHAR(64) PRIMARY KEY,
  attribute_hash      CHAR(64),
  attribute_list      VARCHAR(255),
  first_seen          TIMESTAMP,
  last_seen			  TIMESTAMP
);

COMMIT;

GRANT ALL ON oauth2.dn_records TO 'oa4mp-server'@'localhost';

COMMIT;