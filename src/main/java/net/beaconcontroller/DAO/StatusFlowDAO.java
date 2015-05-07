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

import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatusFlowDAO extends Thread {
    private StatusFlow statusFlow = null;
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    private static int nthread=0;
    private SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss.SSS"); // Datetime format used in Of-IDPS.
    // Mysql
    //private SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS"); // Datetime format required by database.
    // Postgres
    public static SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // Datetime format required by database.
    
    
    
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
    
    public List<StatusFlow> getNormalFlowsUpToSecondsAgo(int seconds) {
        Calendar currentDateTime = Calendar.getInstance();
        currentDateTime.add(Calendar.SECOND, (-1 * seconds));
        String limitDatatime = formatterDB.format(currentDateTime.getTime());
        String sql = "SELECT * FROM flows WHERE tempo >= \'"+limitDatatime+ "\' and flowType = "+StatusFlow.FLOW_NORMAL+";";
        return getFlowsUpToSecondsAgo(seconds, sql);
    }
    
    public List<StatusFlow> getAbnormalFlowsUpToSecondsAgo(int seconds) {
        Calendar currentDateTime = Calendar.getInstance();
        currentDateTime.add(Calendar.SECOND, (-1 * seconds));
        String limitDatatime = formatterDB.format(currentDateTime.getTime());
        String sql = "SELECT * FROM flows WHERE tempo >= \'"+limitDatatime+ "\' and flowType = "+StatusFlow.FLOW_ABNORMAL+";";
        return getFlowsUpToSecondsAgo(seconds, sql);
    }
    
    public List<StatusFlow> getAllFlowsUpToSecondsAgo(int seconds) {
        Calendar currentDateTime = Calendar.getInstance();
        currentDateTime.add(Calendar.SECOND, (-1 * seconds));
        String limitDatatime = formatterDB.format(currentDateTime.getTime());
        String sql = "SELECT * FROM flows WHERE tempo >= \'"+limitDatatime+ "\';";
        return getFlowsUpToSecondsAgo(seconds, sql);
    }
    
    /**
     * Get flows in the database that are equal or greater than current time
     * of system less an amount of seconds (passed by parameter).
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @return - A list of flows between the period of time - current time less seconds set by parameter and current time.
     */
    public synchronized List<StatusFlow> getFlowsUpToSecondsAgo(int seconds, String sql) {
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
     * Insert a flow table register in a database!
     * 
     * Observation: the synchronized parameter was used to avoid that concurrent
     * threads write on the database at same time. Without this the sqlite
     * database presented problems during tests.
     * 
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
        time.add(Calendar.SECOND, (-1 * seconds));
        String limitDatatime = formatterDB.format(time.getTime());
        
        Connection connection = null;
        Statement stmt = null;
        //log.debug("Inserting register in database");
        String sql = "UPDATE flows SET flowType = "+ StatusFlow.FLOW_ABNORMAL +
                " WHERE networkSource = " + networkSource +
                " AND networkDestination = " + networkDestination +
                " AND networkProtocol = " + networkProtocol +
                " AND transportSource = " + transportSource +
                " AND transportDestination = " + transportDestination +
                " AND tempo >= \'"+limitDatatime+ "\'"+
                ";";
        
        log.debug("sql-update: {}",sql);
                
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
