#!/bin/bash
  
E_BADARGS=65
MYSQL=`which psql`
DB_NAME="ofidps"
DB_USER="ofidps"
DB_PASSWORD="123mudar"
    
$MYSQL -U postgres <<EOF
\x
CREATE DATABASE $DB_NAME WITH ENCODING 'UTF8';
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME to $DB_USER;
EOF