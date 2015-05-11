#!/bin/bash
  
E_BADARGS=65
MYSQL=`which psql`
DB_NAME="ofidps"
DB_USER="ofidps"
DB_PASSWORD="123mudar"
      
echo "creating flows table..."
$MYSQL -d $DB_NAME -U $DB_USER -f createTablesFlows_POSTGRES.sql

echo "creating alertsOpenFlow table..."
$MYSQL -d $DB_NAME -U $DB_USER -f createAlertsOpenFlow_POSTGRES.sql
