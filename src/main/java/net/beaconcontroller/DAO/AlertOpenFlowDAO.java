package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.AlertMessageSharePriority;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

//verificar se o problema � nos fluxos que est�o nos switches!

public class AlertOpenFlowDAO {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    
    /**
     * Get all OpenFlow alerts from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - List of OpenFlow alerts.
     */
    public List<AlertMessage> getOpenFlowAlertsUpToSecondsAgo(int seconds) {
        String stringCurrentDateTime = DateTimeManager.getStringDBFromCurrentDate();
        String stringlimitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);        
        String sql = "SELECT * FROM alertsOpenFlow " +
        		"WHERE tempo >= \'"+ stringlimitDatatime+ "\' " +
        				" and tempo <= \'" + stringCurrentDateTime + "\' " +
        				";";
        //log.debug("alertOpenFlow sql: {}", sql);
        return getOpenFlowAlertsUpToSecondsAgo(seconds, sql);
    }
    
    
    public synchronized List<AlertMessage> getOpenFlowAlertsUpToSecondsAgo(int seconds, String sql) {
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
     * Insert a OpenFlow security alert into a database!
     * 
     * Observation: the synchronized parameter was used to avoid that concurrent
     * threads write on the database at same time. Without this the sqlite
     * database presented problems during tests.
     * 
     * @param sf - StatusFlow object to be written into the database.
     */
    public void insert(AlertMessageSharePriority alert) {
        Connection connection = null;
        PreparedStatement stmt = null;
        //log.debug("Inserting register in database.");
        
        //String stringDateAlert = DateTimeManager.formatterDB.format(alert.getTempo());
        String stringDateAlert = DateTimeManager.dateToStringDBDate(alert.getTempo());
        //log.debug("alertOpenFlowDAO - insert: {}, {}", stringDate, stringDateAlert);
        
        String sql = "INSERT INTO alertsOpenFlow ("+
                "tempo,"+
                "priority,"+
                "alertDescription,"+
                "networkSource,"+
                "networkDestination,"+
                "networkProtocol,"+
                "transportSource,"+
                "transportDestination"+
                ")" +
                " VALUES ("+
                    '\''+stringDateAlert+'\''+","+
                    alert.getPriorityAlert()+","+
                    '\''+alert.getAlertDescription()+'\''+","+
                    alert.getNetworkSource()+","+
                    alert.getNetworkDestination()+","+
                    alert.getNetworkProtocol()+","+
                    alert.getTransportSource()+","+
                    alert.getTransportDestination()+
                    ");";
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
            
            //connection = DatabaseManager.getConnection();
            stmt = connection.prepareStatement(sql);
            stmt.executeUpdate();
        } catch (SQLException e) {
            
            // 23505 - duplicate register 
            if(!e.getSQLState().equals("23505")) {
                log.debug("ATTENTION - Sorry wasn't possible to record OpenFlow alert data in database - SQL exception!");
                e.printStackTrace();
            }
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
