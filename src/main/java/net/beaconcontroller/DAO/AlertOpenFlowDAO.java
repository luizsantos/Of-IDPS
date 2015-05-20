/**
 * Used to manage security alerts generated by OpenFlow analysis.
 * 
 * TODO - It has a problem, because some wrong dates appear on the 
 * database, it seems that the trouble is both with the java date 
 * and too with the database.
 */
package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.AlertMessageSharePriority;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;



public class AlertOpenFlowDAO {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    
    /**
     * Get all OpenFlow alerts from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - List of OpenFlow alerts.
     */
    public List<AlertMessage> getOpenFlowAlertsUpToSecondsAgo(int seconds, String comment) {
        String sql = getSQLQueryToGetAlertsUpToSecondsAgo(seconds);
        return getOpenFlowAlertsUpToSecondsAgo(seconds, sql, comment);
    }
    
    /**
     * Get all OpenFlow alerts from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - List of OpenFlow alerts.
     */
    public String getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(int seconds, String comment) {
        String sql = getSQLQueryToGetAlertsUpToSecondsAgo(seconds);
        return getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(seconds, sql, comment);
    }

    /**
     * @param seconds
     * @return
     */
    private String getSQLQueryToGetAlertsUpToSecondsAgo(int seconds) {
        String stringCurrentDateTime = DateTimeManager.getStringDBFromCurrentDate();
        String stringlimitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);        
        String sql = "SELECT * FROM alertsOpenFlow " +
        		"WHERE tempo >= \'"+ stringlimitDatatime+ "\' " +
        				" and tempo <= \'" + stringCurrentDateTime + "\' " +
        				";";
        //log.debug("alertOpenFlow sql: {}", sql);
        return sql;
    }
    
    /**
     * Get a list of OpenFlow alerts using an SQL query.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param sql - SQL query.
     * @param comment - Just a text comment to identify the operation.
     * @return - An alert list.
     */
    public synchronized List<AlertMessage> getOpenFlowAlertsUpToSecondsAgo(int seconds, String sql, String comment) {
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        List<AlertMessage> listOfOpenFlowAlerts = new ArrayList<AlertMessage>();
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
            resultSqlSelect = stmt.executeQuery(sql);
            while (resultSqlSelect.next()) {
                AlertMessage alert = new AlertMessage();
                
                Date alertDate = DateTimeManager.stringDateDBtoJavaDate(resultSqlSelect.getString("tempo"));
                alert.setTempo(alertDate);
                alert.setPriorityAlert(resultSqlSelect.getInt("priority"));
                alert.setAlertDescription(resultSqlSelect.getString("alertDescription"));
                alert.setNetworkSource(resultSqlSelect.getInt("networkSource"));
                alert.setNetworkDestination(resultSqlSelect.getInt("networkDestination"));
                alert.setNetworkProtocol(resultSqlSelect.getInt("networkProtocol"));
                alert.setTransportDestination((short)resultSqlSelect.getInt("transportDestination"));
                alert.setTransportSource((short)resultSqlSelect.getInt("transportSource"));
                listOfOpenFlowAlerts.add(alert);
            }
            log.debug("{} OpenFlow alerts - {}", listOfOpenFlowAlerts.size(), comment);
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from flows table!");
            e.printStackTrace();
        } finally {
            if(resultSqlSelect != null) {
                try {
                    resultSqlSelect.close();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
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
        return listOfOpenFlowAlerts;
    }
    
    /**
     * Get an itemset algorithm string of OpenFlow alerts using an SQL query.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param sql - SQL query.
     * @param comment - Just a text comment to identify the operation.
     * @return - An itemset string with the alerts.
     */
    public synchronized String getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(int seconds, String sql, String comment) {
        String stringAlertsOpenFlow = "";
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        //List<AlertMessage> listOfOpenFlowAlerts = new ArrayList<AlertMessage>();
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
            resultSqlSelect = stmt.executeQuery(sql);
            int alertsTotal=0;
            while (resultSqlSelect.next()) {
                AlertMessage alert = new AlertMessage();
                
                alert.setPriorityAlert(resultSqlSelect.getInt("priority"));
                alert.setAlertDescription(resultSqlSelect.getString("alertDescription"));
                alert.setNetworkSource(resultSqlSelect.getInt("networkSource"));
                alert.setNetworkDestination(resultSqlSelect.getInt("networkDestination"));
                alert.setNetworkProtocol(resultSqlSelect.getInt("networkProtocol"));
                alert.setTransportDestination((short)resultSqlSelect.getInt("transportDestination"));
                alert.setTransportSource((short)resultSqlSelect.getInt("transportSource"));
                stringAlertsOpenFlow = stringAlertsOpenFlow + alert.getStringAlertToBeProcessedByItemsetAlgorithm();
                alertsTotal++;
                
//                int pri = resultSqlSelect.getInt("priority");
//                String des = resultSqlSelect.getString("alertDescription");
//                int src = resultSqlSelect.getInt("networkSource");
//                int dst = resultSqlSelect.getInt("networkDestination");
//                int pro = resultSqlSelect.getInt("networkProtocol");
//                int dpo = (short)resultSqlSelect.getInt("transportDestination");
//                int spo = (short)resultSqlSelect.getInt("transportSource");
//                stringAlertsOpenFlow = stringAlertsOpenFlow + AlertMessage.getStringAlertToBeProcessedByItemsetAlgorithm(src, dst, pro, spo, dpo, pri, des);
//                alertsTotal++;
            }
            log.debug("{} OpenFlow alerts - {}", alertsTotal, comment);
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from flows table!");
            e.printStackTrace();
        } finally {
            if(resultSqlSelect != null) {
                try {
                    resultSqlSelect.close();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
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
        return stringAlertsOpenFlow;
    }
    
    /**
     * Insert a OpenFlow security alert into a database!
     * 
     * Observation: the synchronized parameter was used to avoid that concurrent
     * threads write on the database at same time. Without this the sqlite
     * database presented problems during tests.
     * 
     * @param sf
     *            - StatusFlow object to be written into the database.
     */
    public void insert(AlertMessageSharePriority alert) {
        
        /*
         * Dates to verify is this alert don't has a bad date, 
         * like year 2055 or 0073.
         * 
         * We are have problems with dates on postgresql database 
         * and it is a palliative correction.
         * 
         * Seem that this problem occur both: 
         * here with the Java dates and too in the database.
         * 
         * TODO - Correct the problem of wrong date and time.
         * 
         */
        Date currentDate = DateTimeManager.getCurrentDate();
        Date currentDateLessSomeSeconds = DateTimeManager
                .dateLessAmountOfSeconds(currentDate, 1800); // 1800 seconds =
                                                             // 30 minutes
        Date currentDatePlusSomeSeconds = DateTimeManager
                .datePlusAmountOfSeconds(currentDate, 1800);
        /*
         * Only insert the alert on the database if him has your date: 
         * 30 minutes before or after the current time.
         */
        if (DateTimeManager.isBetweenTheDates(currentDateLessSomeSeconds,
                currentDatePlusSomeSeconds, alert.getTempo())) {

            Connection connection = null;
            PreparedStatement stmt = null;
            // log.debug("Inserting register in database.");

            // String stringDateAlert =
            // DateTimeManager.formatterDB.format(alert.getTempo());
            String stringDateAlert = DateTimeManager.dateToStringDBDate(alert.getTempo());
            // log.debug("alertOpenFlowDAO - insert: {}, {}", stringDate,
            // stringDateAlert);

            String sql = "INSERT INTO alertsOpenFlow (" + "tempo,"
                    + "priority," + "alertDescription," + "networkSource,"
                    + "networkDestination," + "networkProtocol,"
                    + "transportSource," + "transportDestination" + ")"
                    + " VALUES (" + '\'' + stringDateAlert + '\'' + ","
                    + alert.getPriorityAlert() + "," + '\''
                    + alert.getAlertDescription() + '\'' + ","
                    + alert.getNetworkSource() + ","
                    + alert.getNetworkDestination() + ","
                    + alert.getNetworkProtocol() + ","
                    + alert.getTransportSource() + ","
                    + alert.getTransportDestination() + ");";
            // log.debug("sql={}",sql);

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

                // 23505 - duplicate register
                if (!e.getSQLState().equals("23505")) {
                    log.debug("ATTENTION - Sorry wasn't possible to record OpenFlow alert data in database - SQL exception!");
                    alert.printMsgAlert();
                    e.printStackTrace();
                }
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
        } else {
            // if date of alert is out of time!
            log.debug("ATTENTION!!! OpenFlow alert out of date! {} - <{}> - {}", 
                    DateTimeManager.dateToStringJavaDate(currentDateLessSomeSeconds),
                    DateTimeManager.dateToStringJavaDate(alert.getTempo()),
                    DateTimeManager.dateToStringJavaDate(currentDatePlusSomeSeconds));
            alert.printMsgAlert();
        }

    }
        
}
