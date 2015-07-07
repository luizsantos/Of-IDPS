#!/bin/bash
  
E_BADARGS=65
MYSQL=`which psql`
DB_NAME="snort"
DB_USER="snort"
DB_PASSWORD="123mudar"
      
echo "creating extra snort alert comments..."
$MYSQL -d $DB_NAME -U $DB_USER -f createAlertSnortComments_POSTGRES.sql
