package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Iterator;
import java.util.Map;

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.AlertSnort;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityRulesDAO extends Thread {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    /**
     * Insert a list of rules into a database.
     * @param memoryList - List of rules/alerts.
     * @param memoryType - To identify the memory (sensorial, short, long...)
     * @throws SQLException 
     */
    public synchronized void updateRulesFromAMemoryInDB(Map<String,AlertMessage> memoryList, int memoryType) {
        deleteRulesFromAMemory(memoryType);
        for(String key: memoryList.keySet()) {
            AlertMessage rule = memoryList.get(key);
            insert(rule, memoryType);
        }
    }
    
    /**
     * Insert a security rule into a database!
     * 
     * @param rule - A security rule.
     * @param memoryType - Identify the memory (sensorial, short, long...)
     */
    private void insert(AlertMessage rule, int memoryType) {
        Connection connection = null;
        PreparedStatement stmt = null;
        // log.debug("Inserting register in database.");
        
        // used to store the snort alert id!
        int snortAlertId=-1;
        // verify if not is a: none description, a OpenFlow analysis description, or good memory rule.
        if(!rule.getAlertDescription().equals("none") &&
                !rule.getAlertDescription().equals("OF_DoS") &&
                !rule.getAlertDescription().endsWith("good")) {
            // Convert string to integer!
            try {
                int alertId = Integer.parseInt(rule.getAlertDescription());
                // Using the barnyard id get the snort alert id on the database.
                SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
                AlertSnort alertSnort = snortAlertMessageDAO
                        .getSnortAlertIdUsingBarnyardId(alertId);
                // Put the retrieved snort id and description on correct fields!
                rule.setAlertDescription(alertSnort.getDescription());
                snortAlertId = alertSnort.getId();
            } catch (NumberFormatException nfe) {
                log.debug(">>>>>>>>Error to convert "
                        + rule.getAlertDescription() + " to integer number!");
            }
            
        }

        String sql = "INSERT INTO securityRules (" + "memory," + "priority,"
                + "alertDescription," + "networkSource,"
                + "networkDestination," + "networkProtocol,"
                + "transportSource," + "transportDestination," 
                + "supportApriori," +  "life," +  "averagePacketsMatchInOfControllerPerHop,"
                + "totalPacketsMatchInOfController," + "averageOfTotalPacketsMatchInOfControllerPerSeconds,"
                + "ids_alert_id"
                + ")"
                + " VALUES (" + memoryType + ","
                + '\'' + rule.getPriorityAlertString() + '\'' + ","
                + '\'' + rule.getAlertDescription() + '\'' + ","
                + '\'' + rule.getNetworkSourceIPv4String() + '\'' + ","
                + '\'' + rule.getNetworkDestinationIPv4String() + '\'' + ","
                + '\'' + rule.getNetworkProtocolString() + '\'' + ","
                + '\'' + rule.getTransportSourceString() + '\'' + ","
                + '\'' + rule.getTransportDestinationString() + '\'' + ","
                + rule.getSupportApriori() + ","
                + rule.getLife() + ","
                + rule.getAveragePacketsMatchInOfControllerPerHop() + ","
                + rule.getTotalPacketsMatchInOfController() + ","
                + rule.getAverageOfTotalPacketsMatchInOfControllerPerSeconds()  + ","
                + snortAlertId 
                + ");";
         //log.debug("sql={}",sql);

        // Get database connection.
        try {
            DataSource ds;
            try {
                ds = DataSource.getInstance();
                connection = ds.getConnection();
            } catch (PropertyVetoException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            // connection = DatabaseManager.getConnection();
            stmt = connection.prepareStatement(sql);
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.debug("ATTENTION - Sorry wasn't possible to record rule in database - SQL exception!");
            rule.printMsgAlert();
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

        }

    }
    
    private void deleteRulesFromAMemory(int memoryType) {
        String sql = "DELETE FROM securityRules WHERE memory=" + memoryType + ";";
        try {
            update(sql);
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            log.debug("SQL error to delete security rules!!!!");
            e.printStackTrace();
        }
    }
    
    /**
     * Update a rules.
     * @param sql - SQL expression.
     * @throws SQLException
     */
    private void update(String sql) throws SQLException {
        Connection connection = null;
        Statement stmt = null;
        // Get database connection.
        try {
            DataSource ds;
            try {
                ds = DataSource.getInstance();
                connection = ds.getConnection();
            } catch (PropertyVetoException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            stmt = connection.createStatement();
            stmt.executeUpdate(sql);
            
        } catch (SQLException e) {
            log.debug("ATTENTION - Sorry wasn't possible to record data in database - SQL exception!");
            e.printStackTrace();
        } finally {
            if(stmt != null ) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            if (connection != null ) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            
        }
    }

}
