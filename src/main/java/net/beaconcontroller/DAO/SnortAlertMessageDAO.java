/*
 * Used to deal Snort IDS security alerts on the database. 
 * Mainly in the alerts recovery, because the Snort IDS is a sensor.  
 * 
 * ATTENTION!! - Beacon and snort use different kinds of variables 
 * to represent network IP and ports, thus are necessary translations.
 *          | Beacon  | Snort
 *    ------+---------+-----------
 *     IP   | Integer | BigInteger
 *     Port | Short   | Integer
 * 
 */
package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.tools.IpAddress;
import net.beaconcontroller.tools.ProtocolsNumbers;
import net.beaconcontroller.tools.TransportPorts;
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
        
//        log.debug("Alerts from IDS");
//        for(AlertMessage alert : listOfReturnedSnortAlerts) {
//            alert.printMsgAlert();
//        }
        
        
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
            
            // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
            int integerShortSourcePort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("udp_sport"));
            alert.setTransportSource(integerShortSourcePort);
            // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
            int integerShortDestinationPort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("udp_dport"));
            alert.setTransportDestination(integerShortDestinationPort);
            
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
            
            // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
            int integerShortSourcePort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("tcp_sport"));
            alert.setTransportSource(integerShortSourcePort);
            // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
            int integerShortDestinationPort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("tcp_dport"));
            alert.setTransportDestination(integerShortDestinationPort);
            
            listOfReturnedSnortAlerts.add(alert);
        }
    }
    
    public int verifyIfFlowHadSnortAlerts(
            int networkSource, 
            int networkDestination,
            int networkProtocol,
            int transportSource,
            int transportDestination,
            int seconds ) {
        Calendar currentDateTime = Calendar.getInstance();
        currentDateTime.add(Calendar.SECOND, (-1 * seconds));
        String limitDatatime = formatterDB.format(currentDateTime.getTime());
        
        /*
         * Beacon deal integer IP format and snort BigInteger, then we translate it here.
         */
        BigInteger networkSourceBig = IpAddress.parseIntegerIPv4toBigInteger(networkSource);
        BigInteger networkDestinationBig = IpAddress.parseIntegerIPv4toBigInteger(networkDestination);
        
        
        String sql="";
        if(networkProtocol==ProtocolsNumbers.TCP) {
            sql="select count(*) " +
                    " from event e, iphdr i, tcphdr t " +
                    " where e.cid=i.cid " +
                    " and e.sid=i.sid " +
                    " and t.cid=e.cid " +
                    " and t.sid=e.sid " +
                    
                    
                    
                    " and ((" +
                    " i.ip_src= " + networkSourceBig.toString() +
                    " and " +
                    " i.ip_dst= " + networkDestinationBig.toString() +
                    " ) or (" +
                    " i.ip_src= " + networkDestinationBig.toString() +
                    " and " +
                    " i.ip_dst= " + networkSourceBig.toString() +
                    "))" +
                    
                    " and i.ip_proto= " + networkProtocol +
                    
                    " and (" +
                    "    t.tcp_sport= " + transportSource +
                    " or t.tcp_dport= " + transportDestination +
                    " or t.tcp_sport= " + transportDestination +
                    " or t.tcp_dport= " + transportSource +
                    ")" +
                    
                    " and timestamp >= \'"+ limitDatatime+"\';";
        } else if (networkProtocol==ProtocolsNumbers.UDP) {
            sql="select count(*) " +
                    " from event e, iphdr i, udphdr t " +
                    " where e.cid=i.cid " +
                    " and e.sid=i.sid " +
                    " and t.cid=e.cid " +
                    " and t.sid=e.sid " +

                    " and ((" +
                    " i.ip_src= " + networkSourceBig.toString() +
                    " and " +
                    " i.ip_dst= " + networkDestinationBig.toString() +
                    " ) or (" +
                    " i.ip_src= " + networkDestinationBig.toString() +
                    " and " +
                    " i.ip_dst= " + networkSourceBig.toString() +
                    "))" +
                    
                    " and i.ip_proto= " + networkProtocol +
                    
                    " and (" +
                    "    t.udp_sport= " + transportSource +
                    " or t.udp_dport= " + transportDestination +
                    " or t.udp_sport= " + transportDestination +
                    " or t.udp_dport= " + transportSource +
                    ")" +
                    
                    " and timestamp >= \'"+ limitDatatime+"\';";
        } else if (networkProtocol==ProtocolsNumbers.ICMP) {
            sql="select count(*) " +
            		" from event e, iphdr i, icmphdr t " +
            		" where e.cid=i.cid " +
            		" and e.sid=i.sid " +
            		" and t.cid=e.cid " +
            		" and t.sid=e.sid " +
            		
            		" and ((" +
                    " i.ip_src= " + networkSourceBig.toString() +
                    " and " +
                    " i.ip_dst= " + networkDestinationBig.toString() +
                    " ) or (" +
                    " i.ip_src= " + networkDestinationBig.toString() +
                    " and " +
                    " i.ip_dst= " + networkSourceBig.toString() +
                    "))" +
                    
                    " and i.ip_proto= " + networkProtocol +
                    
                    " and ((" +
                    " t.icmp_type= " + transportSource +
                    " and " +
                    " t.icmp_code= " + transportDestination +
                    " ) or (" +
                    " t.icmp_code= " + transportDestination +
                    " and " +
                    " t.icmp_type= " + transportSource +
                    "))" +
            		
            		" and timestamp >= \'"+ limitDatatime+"\';";
        } else {
            log.debug("ATTENTION! Unknown protocol!");
            return 0;
        }
        
        int count = getCountOfSnortAlertsReturned(sql);
        
        log.debug("Bad alert/flowTCP number {}, from sql {}", count, sql);
        
        
        
        return count;
    }
    
    /**
     * Get the number of register returned from a SQL query in the Snort database.
     * @return - Number of register returned from DB.
     */
    public synchronized int getCountOfSnortAlertsReturned(String sql) {
        int count=0; // store the number of register returned from DB;
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
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
            
            resultSqlSelect = stmt.executeQuery(sql);
            
            while(resultSqlSelect.next()) {
                count=resultSqlSelect.getInt(1);
            }
            
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
        
        return count;
        
    }
    

}
