#!/bin/bash
  
E_BADARGS=65
MYSQL=`which mysql`
DB_NAME="OF_IDPS"
DB_USER="root"
DB_PASSWORD="123mudar"
      
echo "creating flows tables..."
$MYSQL $DB_NAME -u$DB_USER --password=$DB_PASSWORD < createTablesFlows.sql
echo "flows tables created!"
