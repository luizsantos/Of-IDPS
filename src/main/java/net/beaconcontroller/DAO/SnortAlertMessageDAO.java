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
import net.beaconcontroller.tools.Calculation;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tools.IpAddress;
import net.beaconcontroller.tools.ProtocolsNumbers;
import net.beaconcontroller.tools.TransportPorts;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;
import net.beaconcontroller.tutorial.SensorOpenFlow;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnortAlertMessageDAO {
    
    private int totalTCPSnortAlerts=0;
    private int totalUDPSnortAlerts=0; 
    private int totalICMPSnortAlerts=0;
    
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    // 1
    
    /**
     * Get all IDS Snort alerts (TCP/UDP/ICMP) in the database.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of Snort Alerts.
     */
    public synchronized String getItemsetsString_SnortAlerts_1_All(String stringWhoCalled) {
        // Get SQL queries.
        String sql = getSQLQuery_1_All();
        log.debug("1 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);
    }
    
    /**
     * Get SQL query string of all TCP alerts .
     * @return - SQL query string.
     */
    private String getSQLQuery_1_All() {
        String sqlTCP = "SELECT e.sid, e.cid," +
        		" ip.ip_src, ip.ip_dst, ip.ip_proto," +
        		" tcp.tcp_sport, tcp.tcp_dport," +
        		" udp.udp_sport, udp.udp_dport," +
        		" icmp.icmp_type, icmp_code," +
        		" s.sig_id, s.sig_priority, e.timestamp" +
        		" FROM event e RIGHT" +
        		" OUTER JOIN iphdr ip USING(sid,cid) LEFT" +
        		" OUTER JOIN tcphdr tcp USING(sid,cid) LEFT" +
        		" OUTER JOIN udphdr udp USING(sid,cid) LEFT" +
        		" OUTER JOIN icmphdr icmp USING(sid,cid) LEFT" +
        		" OUTER JOIN signature s ON e.signature=s.sig_id";
        return sqlTCP;
    }
        
    // 2
    
    /**
     * Get last Snort alerts using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of Snort Alerts.
     */
    public synchronized String getItemsetsString_SnortAlerts_2_lastUsingLimit(int limit, String stringWhoCalled) {
        // Get SQL queries.
        String sql = getSQLQuery_Alerts_2_lastUsingLimit(limit);
        log.debug("2 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);
    }
    
    /**
     * Get SQL query to get last Snort alerts using a limit number of register to be retrieved.
     * @param limit - Amount of register to be returned.
     * @return - SQL query string.
     */ 
    private String getSQLQuery_Alerts_2_lastUsingLimit(int limit) {
        String sql = "SELECT e.sid, e.cid," +
                " ip.ip_src, ip.ip_dst, ip.ip_proto," +
                " tcp.tcp_sport, tcp.tcp_dport," +
                " udp.udp_sport, udp.udp_dport," +
                " icmp.icmp_type, icmp_code," +
                " s.sig_id, s.sig_priority, e.timestamp" +
                " FROM event e RIGHT" +
                " OUTER JOIN iphdr ip USING(sid,cid) LEFT" +
                " OUTER JOIN tcphdr tcp USING(sid,cid) LEFT" +
                " OUTER JOIN udphdr udp USING(sid,cid) LEFT" +
                " OUTER JOIN icmphdr icmp USING(sid,cid) LEFT" +
                " OUTER JOIN signature s ON e.signature=s.sig_id" +
                " ORDER BY e.sid, e.cid DESC " +
                " LIMIT " + limit +
                ";";
        return sql;
    }
    
    /**
     * Get randomly Snort alerts using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of Snort Alerts.
     */
    public synchronized String getItemsetsString_SnortAlerts_2_1_randomlyUsingLimit(
            int limit, String stringWhoCalled) {
        // Get SQL queries.
        String sql = getSQLQuery_Alerts_2_1_randomlyUsingLimit(limit);
        log.debug("2.1 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);
    }
    
    /**
     * Get SQL query to get randomly Snort alerts using a limit number of register to be retrieved.
     * @param limit - Amount of register to be returned.
     * @return - SQL query string.
     */ 
    private String getSQLQuery_Alerts_2_1_randomlyUsingLimit(int limit) {
        String sql = "SELECT e.sid, e.cid," +
                " ip.ip_src, ip.ip_dst, ip.ip_proto," +
                " tcp.tcp_sport, tcp.tcp_dport," +
                " udp.udp_sport, udp.udp_dport," +
                " icmp.icmp_type, icmp_code," +
                " s.sig_id, s.sig_priority, e.timestamp" +
                " FROM event e RIGHT" +
                " OUTER JOIN iphdr ip USING(sid,cid) LEFT" +
                " OUTER JOIN tcphdr tcp USING(sid,cid) LEFT" +
                " OUTER JOIN udphdr udp USING(sid,cid) LEFT" +
                " OUTER JOIN icmphdr icmp USING(sid,cid) LEFT" +
                " OUTER JOIN signature s ON e.signature=s.sig_id" +
                " ORDER BY RANDOM()" +
                " LIMIT " + limit +
                ";";
        return sql;
    }
    
    /**
     * Get randomly using statistical parameters the Snort Alerts!
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of Snort Alerts.
     */
    public synchronized String getItemsetsString_SnortAlerts_2_2_getStatisticUsingLimit(String stringWhoCalled) {
        String selectCount = getSQLQuery_Alerts_countAll();
        int totalRegisters = getCountSnortAlertsFromDatabase(selectCount);
        int limit = (int) Calculation.sampleSize_cofidence95_error5(totalRegisters);
        String sql = getSQLQuery_Alerts_2_1_randomlyUsingLimit(limit);
        log.debug("2.2 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);
    }
    
    // 3
    /**
     * Get all Snort alerts from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of status flows.
     */
    public synchronized String getItemsetsString_SnortAlerts_3_UpToSecondsAgo(
            int seconds, String stringWhoCalled) {
        String sql = getSQLQuery_Alerts_3_upToSecondsAgo(seconds);
        log.debug("3 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);        
    }
    
    /**
     * Get SQL query to get randomly Snort alerts using a limit number of register to be retrieved.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - SQL query string.
     */ 
    private String getSQLQuery_Alerts_3_upToSecondsAgo(int seconds) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT e.sid, e.cid," +
                " ip.ip_src, ip.ip_dst, ip.ip_proto," +
                " tcp.tcp_sport, tcp.tcp_dport," +
                " udp.udp_sport, udp.udp_dport," +
                " icmp.icmp_type, icmp_code," +
                " s.sig_id, s.sig_priority, e.timestamp" +
                " FROM event e RIGHT" +
                " OUTER JOIN iphdr ip USING(sid,cid) LEFT" +
                " OUTER JOIN tcphdr tcp USING(sid,cid) LEFT" +
                " OUTER JOIN udphdr udp USING(sid,cid) LEFT" +
                " OUTER JOIN icmphdr icmp USING(sid,cid) LEFT" +
                " OUTER JOIN signature s ON e.signature=s.sig_id" +
                " WHERE " +
                " timestamp >= \'"+limitDatatime+ "\' and " +
                " timestamp <= \'"+currentDatetime +"\'" +
                ";";
        return sql;
    }
    
    /**
     * Get Snort alerts up to seconds ago, but restrict this search to a amount of register 
     * and get randomly the registers.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of status flows.
     */
    public synchronized String getItemsetsString_SnortAlerts_3_1_randomlyFromSecondsAgo(
            int seconds, int limit, String stringWhoCalled) {
        String sql = getSQLQuery_Alerts_3_1_randomlyFromSecondsAgo(seconds, limit);
        log.debug("3.1 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);        
    }
    
    /**
     * Get SQL query to get Snort alerts up to seconds ago, but restrict this search to a amount of register 
     * and get randomly the registers.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param limit - Amount of register to be returned.
     * @return - SQL query.
     */ 
    private String getSQLQuery_Alerts_3_1_randomlyFromSecondsAgo(int seconds, int limit) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT e.sid, e.cid," +
                " ip.ip_src, ip.ip_dst, ip.ip_proto," +
                " tcp.tcp_sport, tcp.tcp_dport," +
                " udp.udp_sport, udp.udp_dport," +
                " icmp.icmp_type, icmp_code," +
                " s.sig_id, s.sig_priority, e.timestamp" +
                " FROM event e RIGHT" +
                " OUTER JOIN iphdr ip USING(sid,cid) LEFT" +
                " OUTER JOIN tcphdr tcp USING(sid,cid) LEFT" +
                " OUTER JOIN udphdr udp USING(sid,cid) LEFT" +
                " OUTER JOIN icmphdr icmp USING(sid,cid) LEFT" +
                " OUTER JOIN signature s ON e.signature=s.sig_id" +
                " WHERE " +
                " timestamp >= \'"+limitDatatime+ "\' and " +
                " timestamp <= \'"+currentDatetime +"\'" +
                " ORDER BY RANDOM()" +
                " LIMIT "+ limit +
                ";";
        return sql;
    }
    
    /**
     * Get randomly using statistical parameters the last Snort alers up to seconds ago
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of status flows.
     */
    public synchronized String getItemsetsString_SnortAlerts_3_2_getStatisticFromSecondsAgo(
            int seconds, String stringWhoCalled) {
        String selectCount = getSQLQuery_Alerts_countUpToSecondsAgo(seconds);
        int totalRegisters = getCountSnortAlertsFromDatabase(selectCount);
        log.debug("population: {} - sql count: {}", totalRegisters, selectCount);
        int limit = (int) Calculation.sampleSize_cofidence95_error5(totalRegisters);
        String sql = getSQLQuery_Alerts_3_1_randomlyFromSecondsAgo(seconds, limit);
        log.debug("3.2 sql: {}", sql);
        return getItemsetsString_AletsFromDatabase(sql, stringWhoCalled);        
    }
    
    // get all
    
    /**
     * Get SQL query string to count all alerts .
     * @return - SQL query string.
     */
    private String getSQLQuery_Alerts_countAll() {
        String sql = "SELECT count(*)" +
        		" FROM event e RIGHT" +
        		" OUTER JOIN iphdr ip USING(sid,cid);" ;                
        return sql;
    }
    
    /**
     * Get SQL query string to count alerts from now up to seconds ago.
     * @return - SQL query string.
     */
    private String getSQLQuery_Alerts_countUpToSecondsAgo(int seconds) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT count(*)" +
                " FROM event e RIGHT" +
                " OUTER JOIN iphdr ip USING(sid,cid)" +
                " WHERE " +
                " timestamp >= \'"+limitDatatime+ "\' and " +
                " timestamp <= \'"+currentDatetime +"\'" +
                ";" ;     
        return sql;
    }
    
    /**
     * Get the amount of Snort alerts from database.
     * 
     * @param sql - SQL query.
     * @return - Total number of Snort alerts.
     */
    public synchronized int getCountSnortAlertsFromDatabase(String sql) {
        int count=0;
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
            log.debug("ATTENTION - Error during counting alerts Snort from alert table!");
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
    
    /**
     * Get IDS Snort alerts (TCP/UDP/ICMP) in the database that are equal 
     * or greater than current time of system less an amount of seconds 
     * (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - A list of alerts between the period of time - current time less seconds set by parameter and current time.
     */
    public synchronized String getItemsetsString_AletsFromDatabase(String sql, String stringWhoCalled) {
        int totalAlertsRetrieve=0;
        String allAlerts = "";
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
            
            while (resultSqlSelect.next()) {
                //log.debug("get: {}",totalAlertsRetrieve+1);
                AlertMessage alert = new AlertMessage();
                
                alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
                alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
                
                /*
                 * The snort IP address use a long number type, 
                 * but Of-IDPS use a int number type! Thus, it is necessary convert this.
                 */
                long longIpSrc = resultSqlSelect.getLong("ip_src");
                int intIpSrc = (int) (long) longIpSrc;
                alert.setNetworkSource(intIpSrc);
                
                long longIpDst = resultSqlSelect.getLong("ip_dst");
                int intIpDst = (int) (long) longIpDst;
                alert.setNetworkDestination(intIpDst);
                
                alert.setNetworkProtocol(resultSqlSelect.getInt("ip_proto"));
                int integerShortSourcePort=0;
                int integerShortDestinationPort=0;
                switch(alert.getNetworkProtocol()) {
                    case ProtocolsNumbers.TCP:
                        // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
                        integerShortSourcePort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("tcp_sport"));
                        alert.setTransportSource(integerShortSourcePort);
                        // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
                        integerShortDestinationPort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("tcp_dport"));
                        alert.setTransportDestination(integerShortDestinationPort);
                        break;
                    case ProtocolsNumbers.UDP:
                        // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
                        integerShortSourcePort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("udp_sport"));
                        alert.setTransportSource(integerShortSourcePort);
                        // Convert integer port number to short port representation number (used on beacon), but yet in integer number!
                        integerShortDestinationPort = TransportPorts.convertIntegerPortToIntegerShortValue(resultSqlSelect.getInt("udp_dport"));
                        alert.setTransportDestination(integerShortDestinationPort);
                        break;
                    case ProtocolsNumbers.ICMP:
                        alert.setTransportSource(resultSqlSelect.getInt("icmp_type"));
                        alert.setTransportDestination(resultSqlSelect.getInt("icmp_code"));
                        break;
                    default:
                        log.debug("ATTENTION! Network Protocol in a Snort Alert Unknown... (not TCP,UDP,ICMP)");
                }
                
                
                allAlerts = allAlerts + alert.getStringAlertToBeProcessedByItemsetAlgorithm();
                totalAlertsRetrieve++;
                
                
            }
            log.debug("{} SNORT alerts - From {}, ", totalAlertsRetrieve, stringWhoCalled);
            
            
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
        
        
        return allAlerts;
        
    }
       
    /**
     * TODO - REMOVE this method!
     * Get IDS Snort alerts (TCP/UDP/ICMP) in the database that are equal 
     * or greater than current time of system less an amount of seconds 
     * (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - A list of alerts between the period of time - current time less seconds set by parameter and current time.
     */
    public synchronized String getItemsetsString_Alets_TCP_UDP_ICMP(
            String sqlTCP, 
            String sqlUDP,
            String sqlICMP,
            String stringWhoCalled) {
        String allAlerts = "";
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        //List<AlertMessage> listOfReturnedSnortAlerts = new ArrayList<AlertMessage>();
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
            resultSqlSelect = stmt.executeQuery(sqlTCP);
            allAlerts = allAlerts + getItemsetsStringFromTCPAlertsListFromSQLQuery(resultSqlSelect);
            
            // UDP
            resultSqlSelect = stmt.executeQuery(sqlUDP);
            allAlerts = allAlerts + getItemsetsStringFromUDPAlertsListFromSQLQuery(resultSqlSelect);
            
            // ICMP
            resultSqlSelect = stmt.executeQuery(sqlICMP);
            allAlerts = allAlerts + getItemsetsStringFromICMPAlertsListFromSQLQuery(resultSqlSelect);
            
            log.debug("{} - TCP, {} - UDP, {} ICMP SNORT alerts - From {}, ", totalTCPSnortAlerts, totalUDPSnortAlerts, totalICMPSnortAlerts, stringWhoCalled);
            
            
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
        
        
        return allAlerts;
        
    }
    // get all
    
    /**
     * Get IDS Snort alerts (TCP/UDP/ICMP) in the database that are equal 
     * or greater than current time of system less an amount of seconds 
     * (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - A list of alerts between the period of time - current time less seconds set by parameter and current time.
     */
    public synchronized List<AlertMessage> getSnortAlertsUpToSecondsAgo(int seconds, String stringWhoCalled) {
        String limitDatetime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
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
            String sqlTCP = getSQLQueryOfTCPSnortAlertsUpToSecondsAgo(limitDatetime, currentDatetime);
            resultSqlSelect = stmt.executeQuery(sqlTCP);
            getTCPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            int totalTCPSnortAlerts = listOfReturnedSnortAlerts.size();
            
            
            // UDP
            String sqlUDP = getSQLQueryOfUDPSnortAlertsUpToSecondsAgo(limitDatetime, currentDatetime);
            resultSqlSelect = stmt.executeQuery(sqlUDP);
            getUDPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            int totalUDPSnortAlerts = listOfReturnedSnortAlerts.size() - totalTCPSnortAlerts;
            
            // ICMP
            String sqlICMP = getSQLQueryOfICMPSnortAlertsUpToSecondsAgo(limitDatetime, currentDatetime);
            resultSqlSelect = stmt.executeQuery(sqlICMP);
            getICMPAlertsListFromSQLQuery(resultSqlSelect,listOfReturnedSnortAlerts);
            
            int totalICMPSnortAlerts = listOfReturnedSnortAlerts.size() - totalTCPSnortAlerts - totalUDPSnortAlerts;
            log.debug("{} - TCP, {} - UDP, {} ICMP SNORT alerts - From {}, ", totalTCPSnortAlerts, totalUDPSnortAlerts, totalICMPSnortAlerts, stringWhoCalled);
            
            
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
     * Get SQL query string of ICMP alerts up to seconds ago. 
     * @param limitDatetime - Start date.
     * @param currentDatetime - Stop date
     * @return - SQL query string.
     */
    private String getSQLQueryOfICMPSnortAlertsUpToSecondsAgo(
            String limitDatetime, String currentDatetime) {
        String sqlICMP = "SELECT ip_src,ip_dst,ip_proto,t.icmp_type,t.icmp_code,sig_id,sig_priority,timestamp " +
                "FROM event e, iphdr i, signature s, icmphdr t " +
                "WHERE timestamp >= \'"+limitDatetime+ "\' and timestamp <= \'"+currentDatetime+ "\'"+
                		" and e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
        return sqlICMP;
    }

    /**
     * Get SQL query string of UDP alerts up to seconds ago.
     * @param limitDatetime - Start date.
     * @param currentDatetime - Stop date
     * @return - SQL query string.
     */
    private String getSQLQueryOfUDPSnortAlertsUpToSecondsAgo(String limitDatetime,
            String currentDatetime) {
        String sqlUDP = "SELECT ip_src,ip_dst,ip_proto,t.udp_sport,t.udp_dport,sig_id,sig_priority,timestamp " +
                "FROM event e, iphdr i, signature s, udphdr t " +
                "WHERE timestamp >= \'"+limitDatetime+ "\' and timestamp <= \'"+currentDatetime+ "\'"+
                		" and e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
        return sqlUDP;
    }

    /**
     * Get SQL query string of TCP alerts up to seconds ago.
     * @param limitDatetime - Start date.
     * @param currentDatetime - Stop date
     * @return - SQL query string.
     */
    private String getSQLQueryOfTCPSnortAlertsUpToSecondsAgo(String limitDatetime,
            String currentDatetime) {
        String sqlTCP = "SELECT ip_src,ip_dst,ip_proto,t.tcp_sport,t.tcp_dport,sig_id,sig_priority,timestamp " +
                "FROM event e, iphdr i, signature s, tcphdr t " +
                "WHERE timestamp >= \'"+limitDatetime+ "\' and timestamp <= \'"+currentDatetime+ "\'"+
                		" and e.cid=i.cid and e.sid=i.sid and e.signature=s.sig_id and t.cid=e.cid and t.sid=e.sid;";
        return sqlTCP;
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
    
    /**
     * Get an itemset algorithm string of TCP alerts returned from the database and put on the security alert list.
     * 
     * @param resultSqlSelect - SQL select result.
     * @param listOfReturnedSnortAlerts - List of security alerts.
     * @throws SQLException
     * @return - An itemset string with the alerts. 
     */
    private String getItemsetsStringFromTCPAlertsListFromSQLQuery(ResultSet resultSqlSelect) throws SQLException {
        totalTCPSnortAlerts = 0;
        String stringAlertsTCP="";
        while (resultSqlSelect.next()) {
            AlertMessage alert = new AlertMessage();
            
            //alert.setTempo(resultSqlSelect.getTimestamp("timestamp"));
            alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
            alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
            
            /*
             * The snort IP address use a long number type, 
             * but Of-IDPS use a int number type! Thus, it is necessary convert this.
             */
            long longIpSrc = resultSqlSelect.getLong("ip_src");
            int intIpSrc = (int) (long) longIpSrc;
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
            
            stringAlertsTCP = stringAlertsTCP + alert.getStringAlertToBeProcessedByItemsetAlgorithm();
            totalTCPSnortAlerts++;
        }
        return stringAlertsTCP;
    }
    
    /**
     * Get an itemset algorithm string of UDP alerts returned from the database and put on the security alert list.
     * 
     * @param resultSqlSelect - SQL select result.
     * @param listOfReturnedSnortAlerts - List of security alerts.
     * @throws SQLException
     */
    private String getItemsetsStringFromUDPAlertsListFromSQLQuery(ResultSet resultSqlSelect) throws SQLException {
        totalUDPSnortAlerts=0;
        String stringAlertsUDP = "";
        while (resultSqlSelect.next()) {
            AlertMessage alert = new AlertMessage();
            
            //alert.setTempo(resultSqlSelect.getTimestamp("timestamp"));
            alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
            alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
            
            /*
             * The snort IP address use a long number type, 
             * but Of-IDPS use a int number type! Thus, it is necessary convert this.
             */
            long longIpSrc = resultSqlSelect.getLong("ip_src");
            int intIpSrc = (int) (long) longIpSrc;
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
            
            stringAlertsUDP = stringAlertsUDP + alert.getStringAlertToBeProcessedByItemsetAlgorithm();
            totalUDPSnortAlerts++;
        }
        return stringAlertsUDP;
    }
    
    /**
     * Get an itemset algorithm string of ICMP alerts returned from the database and put on the security alert list.
     * 
     * @param resultSqlSelect - SQL select result.
     * @param listOfReturnedSnortAlerts - List of security alerts.
     * @throws SQLException
     */
    private String getItemsetsStringFromICMPAlertsListFromSQLQuery(ResultSet resultSqlSelect) throws SQLException {
        totalICMPSnortAlerts=0;
        String stringAlertsICMP = "";
        while (resultSqlSelect.next()) {
            AlertMessage alert = new AlertMessage();
            
            //alert.setTempo(resultSqlSelect.getTimestamp("timestamp"));
            alert.setAlertDescription(String.valueOf(resultSqlSelect.getInt("sig_id")));
            alert.setPriorityAlert(resultSqlSelect.getInt("sig_priority"));
            
            /*
             * The snort IP address use a long number type, 
             * but Of-IDPS use a int number type! Thus, it is necessary convert this.
             */
            long longIpSrc = resultSqlSelect.getLong("ip_src");
            int intIpSrc = (int) (long) longIpSrc;
            alert.setNetworkSource(intIpSrc);
            
            long longIpDst = resultSqlSelect.getLong("ip_dst");
            int intIpDst = (int) (long) longIpDst;
            alert.setNetworkDestination(intIpDst);
            
            alert.setNetworkProtocol(resultSqlSelect.getInt("ip_proto"));
            alert.setTransportSource(resultSqlSelect.getInt("icmp_type"));
            alert.setTransportDestination(resultSqlSelect.getInt("icmp_code"));
            
            stringAlertsICMP = stringAlertsICMP + alert.getStringAlertToBeProcessedByItemsetAlgorithm();
            totalICMPSnortAlerts++;
        }
        return stringAlertsICMP;
        
    }
    
    public int verifyIfFlowHadSnortAlerts(
            int networkSource, 
            int networkDestination,
            int networkProtocol,
            int transportSource,
            int transportDestination,
            int seconds ) {
        //Calendar currentDateTime = Calendar.getInstance();
        //currentDateTime.add(Calendar.SECOND, (-1 * seconds));
        //String limitDatatime = DateTimeManager.formatterDB.format(currentDateTime.getTime());
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        
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
        
        //log.debug("Bad alert/flowTCP number {}, from sql {}", count, sql);
        
        
        
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
    
    /**
     * TODO delete
     * Get IDS Snort alerts (TCP/UDP/ICMP) in the database that are equal 
     * or greater than current time of system less an amount of seconds 
     * (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - A list of alerts between the period of time - current time less seconds set by parameter and current time.
     */
    public synchronized String getItemsetsString_SnortAlerts_3_UpToSecondsAgo_Old(
            int seconds, String stringWhoCalled) {
        String limitDatetime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        // Get SQL queries.
        String sqlTCP = getSQLQueryOfTCPSnortAlertsUpToSecondsAgo(limitDatetime, currentDatetime);
        String sqlUDP = getSQLQueryOfUDPSnortAlertsUpToSecondsAgo(limitDatetime, currentDatetime);
        String sqlICMP = getSQLQueryOfICMPSnortAlertsUpToSecondsAgo(limitDatetime, currentDatetime);
        return getItemsetsString_Alets_TCP_UDP_ICMP(sqlTCP, sqlUDP, sqlICMP, stringWhoCalled);
    }
    
    

}
