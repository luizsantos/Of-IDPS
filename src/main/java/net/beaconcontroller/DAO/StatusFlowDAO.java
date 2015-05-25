/**
 * Used to read and write data from flow statistics in the database.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 */
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

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.IntrusionPreventionSystem;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tools.ProtocolsNumbers;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatusFlowDAO extends Thread {
    
    private StatusFlow statusFlow = null;
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    private static int nthread=0;
    
    /**
     * Start the class using the object StatusFlow to be written and the name of database.
     * @param sf - StatusFlow object to be written into database.
     * @throws ClassNotFoundException
     * @throws SQLException
     */
    public StatusFlowDAO(StatusFlow sf) throws ClassNotFoundException, SQLException {
        this.setStatusFlow(sf);       
    }
    
    /**
     * Start the class using only the name of database.
     * 
     * @throws ClassNotFoundException 
     * @throws SQLException
     */
    public StatusFlowDAO() throws ClassNotFoundException, SQLException {

    }
    
    // 1
    
    /**
     * Get itemset string from all normal flows.
     * 
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_1_allFlows() {
        String sql = getSQLQueryTo_ofNormalFlows_1_allFlows();
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    /**
     * Get SQL query to get all normal flows.
     * @return Itemsets string of status flows.
     */
    private String getSQLQueryTo_ofNormalFlows_1_allFlows( ) {
        String sql = "SELECT * FROM flows WHERE " +
                " flowType = "+StatusFlow.FLOW_NORMAL+";";
        return sql;
    }
    
    // 2
    /**
     * Get last normal flows using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_2_lastUsingLimit(int limit) {
        String sql = getSQLQuery_ofNormalFlows_2_latUsingLimit(limit);
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    /**
     * Get SQL query to get get normal flows using a limit number of register to be retrieved. 
     * and get randomly the registers.
     * 
     * @param limit - Amount of register to be returned.
     * @return - SQL query.
     */
    private String getSQLQuery_ofNormalFlows_2_latUsingLimit(int limit) {
        String sql = "SELECT * FROM flows WHERE " +
                " flowType = "+StatusFlow.FLOW_NORMAL+
                " ORDER BY flowid DESC "+
                " LIMIT "+ limit +
                        ";";
        return sql;
    }
    
    /**
     * Get randomly normal flows using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_2_1_randomlyUsingLimit(int limit) {
        String sql = getSQLQuery_ofNormalFlows_2_1_randomlyUsingLimit(limit);
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    /**
     * Get SQL query to get get normal flows using a limit number of register to be retrieved. 
     * and get randomly the registers.
     * 
     * @param limit - Amount of register to be returned.
     * @return - SQL query.
     */
    private String getSQLQuery_ofNormalFlows_2_1_randomlyUsingLimit(int limit) {
        String sql = "SELECT * FROM flows WHERE " +
                " flowType = "+StatusFlow.FLOW_NORMAL+
                " ORDER BY RANDOM()" +
                " LIMIT "+ limit +
                        ";";
        return sql;
    }
    
    /**
     * Get randomly using statistical parameters the last good remembrances!
     * 
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_2_2_getStatisticUsingLimit() {
        String selectCount = getSQLQueryTo_ofNormalFlows_1_countAllFlows();
        int totalRegisters = getCountFlowsFromDatabase(selectCount);
        int requiredPercentage = 10;
        int limit = (totalRegisters*requiredPercentage)/100;
        String sql = getSQLQuery_ofNormalFlows_2_1_randomlyUsingLimit(limit);
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    /**
     * Get SQL query to get all normal flows.
     * @return Itemsets string of status flows.
     */
    private String  getSQLQueryTo_ofNormalFlows_1_countAllFlows( ) {
        String sql = "SELECT count(*) FROM flows WHERE " +
                " flowType = "+StatusFlow.FLOW_NORMAL+";";
        return sql;
    }
    
    // 3
    
    
    /**
     * Get all normal flows from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_3_upToSecondsAgo(int seconds) {
        String sql = getSQLQuery_ofNormalFlows_3_upToSecondsAgo(seconds);
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    /**
     * Get all normal flows from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - List of status flows.
     */
    public List<StatusFlow> getList_NormalFlows_3_upToSecondsAgo(int seconds) {
        String sql = getSQLQuery_ofNormalFlows_3_upToSecondsAgo(seconds);
        return getList_FlowsFromDatabase(sql);
    }
    
    /**
     * Get SQL query to get all normal flows up to seconds ago.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - SQL query.
     */
    private String getSQLQuery_ofNormalFlows_3_upToSecondsAgo(int seconds) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT * FROM flows WHERE " +
                " tempo >= \'"+limitDatatime+ "\' and " +
                " tempo <= \'"+currentDatetime +"\' and" + 
                " flowType = "+StatusFlow.FLOW_NORMAL+";";
        return sql;
    }
    
    /**
     * Get normal flows up to seconds ago, but restrict this search to a amount of register 
     * and get randomly the registers.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param seconds - Amount of register to be returned.
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_3_1_randomlyFromSecondsAgo(int seconds, int limit) {
        String sql = getSQLQuery_ofNormalFlows_3_1_randomlyFromSecondsAgo(seconds, limit);
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    /**
     * Get SQL query to get normal flows up to seconds ago, but restrict this search to a amount of register 
     * and get randomly the registers.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param seconds - Amount of register to be returned.
     * @return - SQL query.
     */
    private String getSQLQuery_ofNormalFlows_3_1_randomlyFromSecondsAgo(int seconds, int limit) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT * FROM flows WHERE " +
                " tempo >= \'"+limitDatatime+ "\' and " +
                " tempo <= \'"+currentDatetime +"\' and" + 
                " flowType = "+StatusFlow.FLOW_NORMAL+
                " ORDER BY RANDOM()" +
                " LIMIT "+ limit +
                		";";
        return sql;
    }
    
    /**
     * Get randomly using statistical parameters the last good remembrances up to seconds ago
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofNormalFlows_3_2_getStatisticFromSecondsAgo(int seconds) {
        String selectCount = getSQLQueryTo_ofNormalFlows_1_countAllFlows();
        int totalRegisters = getCountFlowsFromDatabase(selectCount);
        int requiredPercentage = 10;
        int limit = (totalRegisters*requiredPercentage)/100;
        String sql = getSQLQuery_ofNormalFlows_3_1_randomlyFromSecondsAgo(seconds, limit);
        return getItemsetsString_FlowsFromDatabase(sql);
    }
    
    
    // Others
    
    /**
     * Get all flows (bad and good) from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - List of status flows.
     */
    public List<StatusFlow> getList_GoodBadFlows_upToSecondsAgo(int seconds) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT * FROM flows WHERE " +
                " tempo >= \'"+limitDatatime+ "\' and " +
                " tempo <= \'"+currentDatetime +"\' and" + 
                        ";";
        return getList_FlowsFromDatabase(sql);
    }
    
    
    /**
     * Get all abnormal flows from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - List of status flows.
     */
    private List<StatusFlow> getList_BadFlows_UpToSecondsAgo(int seconds) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT * FROM flows WHERE " +
        		" tempo >= \'"+limitDatatime+ "\' and " +
        		" tempo <= \'"+currentDatetime +"\' and" + 
        	    " flowType = "+StatusFlow.FLOW_ABNORMAL+";";
        return getList_FlowsFromDatabase(sql);
    }
    
    /**
     * Get flows that are suspicious of DoS attacks.
     * Select flows from current time minus an amount of seconds, that have few packets, 
     * and have also few bytes on the flow. 
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param dosTCPPacketCount - Number of TCP packets in a flow.
     * @param dosTCPByteCount - Number of TCP bytes in a flow.
     * @return - List of status flows.
     */
    public List<StatusFlow> getList_suspiciousDoSTCPFlows_upToSecondsAgo(int seconds, int dosTCPPacketCount, int dosTCPByteCount) {
        String currentDatetime = DateTimeManager.getStringDBFromCurrentDate();
        String limitDatatime = DateTimeManager.getStringDBFromCurrentDateLessAmountOfSeconds(seconds);
        String sql = "SELECT * FROM flows " +
        		" WHERE " +
        		" tempo >= \'"+limitDatatime+"\' and" +
        		" tempo <= \'"+currentDatetime +"\' and" + 
        		" networkProtocol = " + ProtocolsNumbers.TCP + " and" +
        		" packetCount <= "+ dosTCPPacketCount +" and" +
        		" byteCount <= " + dosTCPByteCount +
        		";";
        return getList_FlowsFromDatabase(sql);
    }
    
    /**
     * Get flows in the database that are equal or greater than current time
     * of system less an amount of seconds (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - A list of flows between the period of time - current time less seconds set by parameter and current time.
     */
    private synchronized List<StatusFlow> getList_FlowsFromDatabase(String sql) {
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        List<StatusFlow> listOfReturnedFlows = new ArrayList<StatusFlow>();
        
        //log.debug("SQL: "+ sql + " - Current time: "+ formatterDB.format(new Date()));
        
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
                StatusFlow statusFlow = new StatusFlow();
                statusFlow.setFlowId(resultSqlSelect.getInt("flowId"));
                statusFlow.setSwID(resultSqlSelect.getLong("swID"));
                statusFlow.setTimeFromDB(resultSqlSelect.getString("tempo"));
                statusFlow.setByteCount(resultSqlSelect.getLong("byteCount"));
                statusFlow.setCookie(resultSqlSelect.getLong("cookie"));
                statusFlow.setDurationNanoseconds(resultSqlSelect.getInt("durationNanoseconds"));
                statusFlow.setDurationSeconds(resultSqlSelect.getInt("durationSeconds"));
                statusFlow.setHardTimeout((short) resultSqlSelect.getInt("hardTimeout"));
                statusFlow.setIdleTimeout((short) resultSqlSelect.getInt("idleTimeout"));
                statusFlow.setLength((short) resultSqlSelect.getInt("length"));
                statusFlow.setPacketCount(resultSqlSelect.getLong("packetCount"));
                statusFlow.setPriority((short) resultSqlSelect.getInt("priority"));
                // TODO - verify if really table id is byte! and why? verify if this cast don't cause problem!
                statusFlow.setTableId((byte) resultSqlSelect.getInt("tableId"));
                statusFlow.setDataLayerDestination(resultSqlSelect.getBytes("dataLayerDestination"));
                statusFlow.setDataLayerSource(resultSqlSelect.getBytes("dataLayerSource"));
                statusFlow.setDataLayerType((short) resultSqlSelect.getInt("dataLayerType"));
                statusFlow.setDataLayerVirtualLan((short) resultSqlSelect.getInt("dataLayerVirtualLan"));
                // TODO - verify if really VLAN priority is byte! and why? verify if this cast don't cause problem!
                statusFlow.setDataLayerVirtualLanPriorityCodePoint((byte) resultSqlSelect.getInt("dataLayerVirtualLanPriorityCodePoint"));
                statusFlow.setInputPort((short) resultSqlSelect.getInt("inputPort"));
                statusFlow.setNetworkDestination(resultSqlSelect.getInt("networkDestination"));
                statusFlow.setNetworkProtocol((byte) resultSqlSelect.getInt("networkProtocol"));
                statusFlow.setNetworkSource(resultSqlSelect.getInt("networkSource"));
                // TODO - verify if really ToS is byte! and why? verify if this cast don't cause problem!
                statusFlow.setNetworkTypeOfService((byte) resultSqlSelect.getInt("networkTypeOfService"));
                statusFlow.setTransportDestination((short) resultSqlSelect.getInt("transportDestination"));
                statusFlow.setTransportSource((short) resultSqlSelect.getInt("transportSource"));
                statusFlow.setWildcards(resultSqlSelect.getInt("wildcards"));
                //statusFlow.printStatusFlow(x+" - Inside of StatusFlowDAO:");
                statusFlow.setLiveAsDead();
                statusFlow.setFlowType(resultSqlSelect.getInt("flowType"));
                listOfReturnedFlows.add(statusFlow);
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
        return listOfReturnedFlows;
    }
    
    /**
     * Get flows in the database that are equal or greater than current time
     * of system less an amount of seconds (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - A list of flows between the period of time - current time less seconds set by parameter and current time.
     */
    private synchronized String getItemsetsString_FlowsFromDatabase(String sql) {
        String allGoodFlows = "";
        int totalFlows=0;
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        
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
                AlertMessage goodFlow = new AlertMessage();
                goodFlow.setPriorityAlert(AlertMessage.NORMAL_PACKET);
                goodFlow.setAlertDescription("good");
                goodFlow.setNetworkSource(resultSqlSelect.getInt("networkSource"));
                goodFlow.setNetworkDestination(resultSqlSelect.getInt("networkDestination"));
                goodFlow.setNetworkProtocol((byte) resultSqlSelect.getInt("networkProtocol"));
                goodFlow.setTransportSource((short) resultSqlSelect.getInt("transportSource"));
                goodFlow.setTransportDestination((short) resultSqlSelect.getInt("transportDestination"));
                allGoodFlows = allGoodFlows + goodFlow.getStringAlertToBeProcessedByItemsetAlgorithm();
                totalFlows++;
                
            }
            log.debug("{} Good flows/remembrances - {}", totalFlows, "Long Good Memory");
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from good remembrances - Status flow!");
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
        return allGoodFlows;
    }
    
    /**
     * Get flows in the database that are equal or greater than current time
     * of system less an amount of seconds (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - A list of flows between the period of time - current time less seconds set by parameter and current time.
     */
    private synchronized int getCountFlowsFromDatabase(String sql) {
        int count=0; // store the number of register returned from DB;
        Connection connection = null;
        Statement stmt = null;
        ResultSet resultSqlSelect = null;
        
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
            while(resultSqlSelect.next()) {
                count=resultSqlSelect.getInt(1);
            }
            
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select to counting the amount of good remembrances - Status flow!");
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
     * Insert a flow table register in a database!
     * 
     * Observation: the synchronized parameter was used to avoid that concurrent
     * threads write on the database at same time. Without this the sqlite
     * database presented problems during tests.
     * 
     * @param sf - StatusFlow object to be written into the database.
     */
    public void insert(StatusFlow sf) {
        Connection connection = null;
        PreparedStatement stmt = null;
        //log.debug("Inserting register in database.");
        String sql = "INSERT INTO flows ("+
                "swID,"+
                "tempo,"+
                "byteCount,"+
                "cookie,"+
                "durationNanoseconds,"+
                "durationSeconds,"+
                "hardTimeout,"+
                "idleTimeout,"+
                "length,"+
                "packetCount,"+
                "priority,"+
                "tableId,"+
                "dataLayerDestination,"+
                "dataLayerSource,"+
                "dataLayerType,"+
                "dataLayerVirtualLan,"+
                "dataLayerVirtualLanPriorityCodePoint,"+
                "inputPort,"+
                "networkDestination,"+
                "networkProtocol,"+
                "networkSource,"+
                "networkTypeOfService,"+
                "transportDestination,"+
                "transportSource,"+
                "wildcards,"+
                "flowType"+
                ")" +
                " VALUES ("+
                    sf.getSwID()+","+
                    '\''+sf.getTimeStringBD()+'\''+","+
                    sf.getByteCount()+","+
                    sf.getCookie()+","+
                    sf.getDurationNanoseconds()+","+
                    sf.getDurationSeconds()+","+
                    sf.getHardTimeout()+","+
                    sf.getIdleTimeout()+","+
                    sf.getLength()+","+
                    sf.getPacketCount()+","+
                    sf.getPriority()+","+
                    sf.getTableId()+","+
                    "?,"+
                    "?,"+
                    sf.getDataLayerType()+","+
                    sf.getDataLayerVirtualLan()+","+
                    sf.getDataLayerVirtualLanPriorityCodePoint()+","+
                    sf.getInputPort()+","+
                    sf.getNetworkDestination()+","+
                    sf.getNetworkProtocol()+","+
                    sf.getNetworkSource()+","+
                    sf.getNetworkTypeOfService()+","+
                    sf.getTransportDestination()+","+
                    sf.getTransportSource()+","+
                    sf.getWildcards()+","+
                    sf.getFlowType()+
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
            /*
             * The two lines below are necessary because the hardware address are
             * binary, then here we prepare this fields to record correctly.
             */
            stmt.setBytes(1, getStatusFlow().getDataLayerDestination());
            stmt.setBytes(2, getStatusFlow().getDataLayerSource());
            stmt.executeUpdate();
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
    
    /**
     * Insert a flow table register in a database!
     * 
     * Observation: the synchronized parameter was used to avoid that concurrent
     * threads write on the database at same time. Without this the sqlite
     * database presented problems during tests.
     * 
     * @throws SQLException
     */
    public synchronized void insert() throws SQLException {
        Connection connection = null;
        PreparedStatement stmt = null;
        //log.debug("Inserting register in database");
        String sql = "INSERT INTO flows ("+
                "swID,"+
                "tempo,"+
                "byteCount,"+
                "cookie,"+
                "durationNanoseconds,"+
                "durationSeconds,"+
                "hardTimeout,"+
                "idleTimeout,"+
                "length,"+
                "packetCount,"+
                "priority,"+
                "tableId,"+
                "dataLayerDestination,"+
                "dataLayerSource,"+
                "dataLayerType,"+
                "dataLayerVirtualLan,"+
                "dataLayerVirtualLanPriorityCodePoint,"+
                "inputPort,"+
                "networkDestination,"+
                "networkProtocol,"+
                "networkSource,"+
                "networkTypeOfService,"+
                "transportDestination,"+
                "transportSource,"+
                "wildcards,"+
                "flowType"+
                ")" +
                " VALUES ("+
                    getStatusFlow().getSwID()+","+
                    '\''+getStatusFlow().getTimeStringBD()+'\''+","+
                    getStatusFlow().getByteCount()+","+
                    getStatusFlow().getCookie()+","+
                    getStatusFlow().getDurationNanoseconds()+","+
                    getStatusFlow().getDurationSeconds()+","+
                    getStatusFlow().getHardTimeout()+","+
                    getStatusFlow().getIdleTimeout()+","+
                    getStatusFlow().getLength()+","+
                    getStatusFlow().getPacketCount()+","+
                    getStatusFlow().getPriority()+","+
                    getStatusFlow().getTableId()+","+
                    "?,"+
                    "?,"+
                    getStatusFlow().getDataLayerType()+","+
                    getStatusFlow().getDataLayerVirtualLan()+","+
                    getStatusFlow().getDataLayerVirtualLanPriorityCodePoint()+","+
                    getStatusFlow().getInputPort()+","+
                    getStatusFlow().getNetworkDestination()+","+
                    getStatusFlow().getNetworkProtocol()+","+
                    getStatusFlow().getNetworkSource()+","+
                    getStatusFlow().getNetworkTypeOfService()+","+
                    getStatusFlow().getTransportDestination()+","+
                    getStatusFlow().getTransportSource()+","+
                    getStatusFlow().getWildcards()+","+
                    getStatusFlow().getFlowType()+
                    ");";
         /*
         * the commented lines below can be used to verify the numbers of
         * threads used to record in the database.
         */
//            int nthr = getNthread();
//            setNthread();
//            log.debug("Threading {} - >RECORDING<",nthr);
//         log.debug("sql={}",sql);
        
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
            
            stmt = connection.prepareStatement(sql);
            /*
             * The two lines below are necessary because the hardware address are
             * binary, then here we prepare this fields to record correctly.
             */
            stmt.setBytes(1, getStatusFlow().getDataLayerDestination());
            stmt.setBytes(2, getStatusFlow().getDataLayerSource());
            stmt.executeUpdate();
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
    
    /**
     * Update/set a bad flow using some flow fields.
     * @param networkSource - Source address IP.
     * @param networkDestination - Destination address IP.
     * @param networkProtocol - Network protocol (TCP/UDP/ICMP...).
     * @param transportSource - Source port or ICMP type.
     * @param transportDestination - Destination port or ICMP code.
     * @param time - Datetime.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @throws SQLException
     */
    public synchronized void updateBadFlow(
            int networkSource, 
            int networkDestination,
            int networkProtocol,
            int transportSource,
            int transportDestination,
            Calendar time,
            int seconds
            ) throws SQLException {
        
        // The alert time minus an amount of time in seconds to search the flow!
//        time.add(Calendar.SECOND, (-1 * seconds));
//        String limitDatatime = DateTimeManager.formatterDB.format(time.getTime());
        String limitDatatime = DateTimeManager.getStringDBdateLessAmountOfSeconds(time.getTime(), seconds);
        
        String sql = "UPDATE flows SET flowType = "+ StatusFlow.FLOW_ABNORMAL +
                " WHERE networkSource = " + networkSource +
                " AND networkDestination = " + networkDestination +
                " AND networkProtocol = " + networkProtocol +
                " AND transportSource = " + transportSource +
                " AND transportDestination = " + transportDestination +
                " AND tempo >= \'"+limitDatatime+ "\'"+
                " AND flowType <> " + StatusFlow.FLOW_ABNORMAL +
                ";";
        this.update(sql);
    }
    
    /**
     * Update/set a bad flow using the flow identification number.
     * @param flowId - Flow identification number.
     * @throws SQLException
     */
    public synchronized void updateBadFlowByFlowId(int flowId) throws SQLException {
        String sql = "UPDATE flows SET flowType = "+ StatusFlow.FLOW_ABNORMAL +
                " WHERE flowId = " + flowId +
                " AND flowType <> " + StatusFlow.FLOW_ABNORMAL +
                ";";
        
        //log.debug("bad sql: {}",sql);
        
        this.update(sql);
    }
    
    /**
     * Update a flow.
     * @param sql - SQL expression.
     * @throws SQLException
     */
    public synchronized void update(String sql) throws SQLException {
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
    
    /**
     * Thread used to write the data in the database.
     * 
     * this requires that a valid StatusFlow object has been passed, in others
     * works can't be a null object. Then you can use the superclass passing the
     * StatusFlow object and database name or use the setStatusFlow( ) method.
     * 
     * Observation: Without this insert using thread Of-IDPS has presented
     * timeouts error/warning to receive/send OpenFlow messages, then for now is
     * recommended to use it.
     * 
     */
    public void run(){
        if(this.statusFlow!=null) {
            try {
                this.insert();
            } catch (SQLException e) {
                log.debug("ATTENTION - Sorry wasn't possible to record data in database - SQL error!");
                e.printStackTrace();
            }
        } else {
            log.debug("ATTENTION - Was impossible to record this object because it's a null object.");
        }
        
    }

    public StatusFlow getStatusFlow() {
        return statusFlow;
    }

    public void setStatusFlow(StatusFlow statusFlow) {
        this.statusFlow = statusFlow;
    }

    /**
     * Can be used to verify the numbers of threads used to record in the database.
     */
    private synchronized static int getNthread() {
        return nthread;
    }
    /**
     * Can be used to verify the numbers of threads used to record in the database.
     */
    private synchronized static void setNthread() {
        nthread++;
    }


}
