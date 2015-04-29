/*
 * Used to deal Snort IDS security alerts on the database. 
 * Mainly in the alerts recovery, because the Snort IDS is a sensor.  
 */
package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnortAlertMessageDAO {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    // Postgres
    public static SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // Datetime format required by database.
    
    
    /**
     * Get IDS Snort alerts (TCP/UDP/ICMP) in the database that are equal 
     * or greater than current time of system less an amount of seconds 
     * (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - A list of alerts between the period of time - current time less seconds set by parameter and current time.
     */
    public synchronized List<AlertMessage> getSnortAlertsUpToSecondsAgo(int seconds) {
        
        Calendar currentDateTime = Calendar.getInstance();
        currentDateTime.add(Calendar.SECOND, (-1 * seconds));
        String limitDatatime = formatterDB.format(currentDateTime.getTime());
        
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        List<AlertMessage> listOfReturnedSnortAlerts = new ArrayList<AlertMessage>();
        try {
            DataSourceSnortIDS ds;
            try {
                ds = DataSourceSnortIDS.getInstance();
                connection = ds.getConnection();
            } catch (PropertyVetoException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } 
            
            stmt = connection.createStatement();
            
            // TCP
            String sqlTCP = "SELECT ip_src,ip_dst,ip_proto,t.tcp_sport,t.tcp_dport,sig_id,sig_priority,timestamp " +
                    "FROM event e, iphdr i, signature s, tcphdr t " +
                    "WHERE timestamp >= \'"+limitDatatime+ "\' and e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
            resultSqlSelect = stmt.executeQuery(sqlTCP);
            getTCPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            int totalTCPSnortAlerts = listOfReturnedSnortAlerts.size();
            
            
            // UDP
            String sqlUDP = "SELECT ip_src,ip_dst,ip_proto,t.udp_sport,t.udp_dport,sig_id,sig_priority,timestamp " +
                    "FROM event e, iphdr i, signature s, udphdr t " +
                    "WHERE timestamp >= \'"+limitDatatime+ "\' and e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
            resultSqlSelect = stmt.executeQuery(sqlUDP);
            getUDPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            int totalUDPSnortAlerts = listOfReturnedSnortAlerts.size() - totalTCPSnortAlerts;
            
            // ICMP
            String sqlICMP = "SELECT ip_src,ip_dst,ip_proto,t.icmp_type,t.icmp_code,sig_id,sig_priority,timestamp " +
                    "FROM event e, iphdr i, signature s, icmphdr t " +
                    "WHERE timestamp >= \'"+limitDatatime+ "\' and e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
            resultSqlSelect = stmt.executeQuery(sqlICMP);
            getICMPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            
            int totalICMPSnortAlerts = listOfReturnedSnortAlerts.size() - totalTCPSnortAlerts - totalUDPSnortAlerts;
            log.debug("{} - TCP, {} - UDP, {} ICMP Snort alerts, ", totalTCPSnortAlerts, totalUDPSnortAlerts, totalICMPSnortAlerts);
            
            
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from IDS Snort Alert table!");
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
        
        return listOfReturnedSnortAlerts;
        
    }
    
    /**
     * Get All IDS Snort alerts (TCP/UDP/ICMP) in the database.
     * @return - A list of alerts.
     */
    public synchronized List<AlertMessage> getSnortAlerts() {
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        List<AlertMessage> listOfReturnedSnortAlerts = new ArrayList<AlertMessage>();
        try {
            DataSourceSnortIDS ds;
            try {
                ds = DataSourceSnortIDS.getInstance();
                connection = ds.getConnection();
            } catch (PropertyVetoException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } 
            
            stmt = connection.createStatement();
            
            // TCP
            String sqlTCP = "SELECT ip_src,ip_dst,ip_proto,t.tcp_sport,t.tcp_dport,sig_id,sig_priority,timestamp " +
                    "FROM event e, iphdr i, signature s, tcphdr t " +
                    "WHERE e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
            resultSqlSelect = stmt.executeQuery(sqlTCP);
            getTCPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            int totalTCPSnortAlerts = listOfReturnedSnortAlerts.size();
            
            
            // UDP
            String sqlUDP = "SELECT ip_src,ip_dst,ip_proto,t.udp_sport,t.udp_dport,sig_id,sig_priority,timestamp " +
                    "FROM event e, iphdr i, signature s, udphdr t " +
                    "WHERE e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
            resultSqlSelect = stmt.executeQuery(sqlUDP);
            getUDPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            int totalUDPSnortAlerts = listOfReturnedSnortAlerts.size() - totalTCPSnortAlerts;
            
            // ICMP
            String sqlICMP = "SELECT ip_src,ip_dst,ip_proto,t.icmp_type,t.icmp_code,sig_id,sig_priority,timestamp " +
                    "FROM event e, iphdr i, signature s, icmphdr t " +
                    "WHERE e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
            resultSqlSelect = stmt.executeQuery(sqlICMP);
            getICMPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            
            int totalICMPSnortAlerts = listOfReturnedSnortAlerts.size() - totalTCPSnortAlerts - totalUDPSnortAlerts;
            log.debug("{} - TCP, {} - UDP, {} ICMP Snort alerts, ", totalTCPSnortAlerts, totalUDPSnortAlerts, totalICMPSnortAlerts);
            
            
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from IDS Snort Alert table!");
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
        
        return listOfReturnedSnortAlerts;
        
    }

    /**
     * Get the ICMP alerts returned from the database and put on the security alert list.
     * 
     * @param resultSqlSelect - SQL select result.
     * @param listOfReturnedSnortAlerts - List of security alerts.
     * @throws SQLException
     */
    private void getICMPAlertsListFromSQLQuery(ResultSet resultSqlSelect,
            List<AlertMessage> listOfReturnedSnortAlerts) throws SQLException {
        while (resultSqlSelect.next()) {
            AlertMessage alert = new AlertMessage();
            
            alert.setTempo(resultSqlSelect.getTimestamp("timestamp"));
            alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
            alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
            
            /*
             * The snort IP address use a long number type, 
             * but Of-IDPS use a int number type! Thus, it is necessary convert this.
             */
            long longIpSrc = resultSqlSelect.getLong("ip_src");
            int intIpSrc = (int) (long) longIpSrc;
            //String stringIpSrc = IPv4.fromIPv4Address(intIpSrc);
            //System.out.println("ip_src: "+ longIpSrc +" - "+ intIpSrc+" - "+ stringIpSrc);
            alert.setNetworkSource(intIpSrc);
            
            long longIpDst = resultSqlSelect.getLong("ip_dst");
            int intIpDst = (int) (long) longIpDst;
            alert.setNetworkDestination(intIpDst);
            
            alert.setNetworkProtocol(resultSqlSelect.getInt("ip_proto"));
            alert.setTransportSource(resultSqlSelect.getInt("icmp_type"));
            alert.setTransportDestination(resultSqlSelect.getInt("icmp_code"));
            
            listOfReturnedSnortAlerts.add(alert);
        }
    }

    /**
     * Get the UDP alerts returned from the database and put on the security alert list.
     * 
     * @param resultSqlSelect - SQL select result.
     * @param listOfReturnedSnortAlerts - List of security alerts.
     * @throws SQLException
     */
    private void getUDPAlertsListFromSQLQuery(ResultSet resultSqlSelect,
            List<AlertMessage> listOfReturnedSnortAlerts) throws SQLException {
        while (resultSqlSelect.next()) {
            AlertMessage alert = new AlertMessage();
            
            alert.setTempo(resultSqlSelect.getTimestamp("timestamp"));
            alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
            alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
            
            /*
             * The snort IP address use a long number type, 
             * but Of-IDPS use a int number type! Thus, it is necessary convert this.
             */
            long longIpSrc = resultSqlSelect.getLong("ip_src");
            int intIpSrc = (int) (long) longIpSrc;
            //String stringIpSrc = IPv4.fromIPv4Address(intIpSrc);
            //System.out.println("ip_src: "+ longIpSrc +" - "+ intIpSrc+" - "+ stringIpSrc);
            alert.setNetworkSource(intIpSrc);
            
            long longIpDst = resultSqlSelect.getLong("ip_dst");
            int intIpDst = (int) (long) longIpDst;
            alert.setNetworkDestination(intIpDst);
            
            alert.setNetworkProtocol(resultSqlSelect.getInt("ip_proto"));
            alert.setTransportSource(resultSqlSelect.getInt("udp_sport"));
            alert.setTransportDestination(resultSqlSelect.getInt("udp_dport"));
            
            listOfReturnedSnortAlerts.add(alert);
        }
    }

    /**
     * Get the TCP alerts returned from the database and put on the security alert list.
     * 
     * @param resultSqlSelect - SQL select result.
     * @param listOfReturnedSnortAlerts - List of security alerts.
     * @throws SQLException
     */
    private void getTCPAlertsListFromSQLQuery(ResultSet resultSqlSelect,
            List<AlertMessage> listOfReturnedSnortAlerts) throws SQLException {
        while (resultSqlSelect.next()) {
            AlertMessage alert = new AlertMessage();
            
            alert.setTempo(resultSqlSelect.getTimestamp("timestamp"));
            alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
            alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
            
            /*
             * The snort IP address use a long number type, 
             * but Of-IDPS use a int number type! Thus, it is necessary convert this.
             */
            long longIpSrc = resultSqlSelect.getLong("ip_src");
            int intIpSrc = (int) (long) longIpSrc;
            //String stringIpSrc = IPv4.fromIPv4Address(intIpSrc);
            //System.out.println("ip_src: "+ longIpSrc +" - "+ intIpSrc+" - "+ stringIpSrc);
            alert.setNetworkSource(intIpSrc);
            
            long longIpDst = resultSqlSelect.getLong("ip_dst");
            int intIpDst = (int) (long) longIpDst;
            alert.setNetworkDestination(intIpDst);
            
            alert.setNetworkProtocol(resultSqlSelect.getInt("ip_proto"));
            alert.setTransportSource(resultSqlSelect.getInt("tcp_sport"));
            alert.setTransportDestination(resultSqlSelect.getInt("tcp_dport"));
            
            listOfReturnedSnortAlerts.add(alert);
        }
    }
    

}
