package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.text.SimpleDateFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.IPS.AlertMessageSharePriority;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

public class AlertOpenFlowDAO {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    // Postgres
    public static SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS"); // Datetime format required by database.
    
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
                    '\''+alert.getTempoStringBD()+'\''+","+
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
            log.debug("ATTENTION - Sorry wasn't possible to record alert data in database - SQL exception!");
            // duplicate register
            if(e.getSQLState().equals("23505")) {
                System.out.println("WARNING!!!" + e.getMessage());
            } else {
                System.out.println("Erro during insert alert on AlertOpenFlow table!");
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
