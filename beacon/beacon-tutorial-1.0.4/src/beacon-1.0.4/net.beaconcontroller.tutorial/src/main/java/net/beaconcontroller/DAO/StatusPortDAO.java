/**
 * Used to read and write data from switches ports statistics in the database.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 * TODO - IMPORTANT - we need adjust this to access the new Mysql database, 
 * we need use threads, connection pooling, change table create, change time 
 * attribute, all this must be made like StatusFlowDAO...
 *  
 */
package net.beaconcontroller.DAO;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Vector;

import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatusPortDAO {
    private Connection c;
    private Statement stmt;
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    public StatusPortDAO(String fileName) throws ClassNotFoundException, SQLException {
        /*
         * TODO - CAUTION... we need Adjust this to access 
         * the new Mysql database and connection pooling, thread... 
         * like was made in StatusFlowDAO.           
         */
        //log.debug("Start database.");
        Class.forName("org.sqlite.JDBC");
        c = DriverManager.getConnection("jdbc:sqlite:"+fileName);
        stmt = (Statement) c.createStatement();
    }
    
    public void close() throws SQLException {
        //log.debug("Close database.");
        stmt.close();
        c.close();
    }
    
    public void insert(StatusPort statusPorta) throws SQLException {
        //log.debug("Add status port message in database.");
        String sql = "INSERT INTO ports (" +
                "switchNumber,"+
                "portNumber,"+
                "collisions,"+
                "receiveBytes,"+
                "receiveCRCErrors,"+
                "receiveDropped,"+
                "receiveErrors,"+
                "receiveFrameErrors,"+
                "receiveOverrunErrors,"+
                "receivePackets,"+
                "transmitBytes,"+
                "transmitDropped,"+
                "transmitErrors,"+
                "transmitPackets,"+
                "tempo"+
                ")" +
                "VALUES ("+
                    statusPorta.getSwID()+","+
                    statusPorta.getPortNumber()+","+
                    statusPorta.getCollisions()+","+
                    statusPorta.getReceiveBytes()+","+
                    statusPorta.getReceiveCRCErrors()+","+
                    statusPorta.getReceiveDropped()+","+
                    statusPorta.getreceiveErrors()+","+
                    statusPorta.getReceiveFrameErrors()+","+
                    statusPorta.getReceiveOverrunErrors()+","+
                    statusPorta.getreceivePackets()+","+
                    statusPorta.getTransmitBytes()+","+
                    statusPorta.getTransmitDropped()+","+
                    statusPorta.getTransmitErrors()+","+
                    statusPorta.getTransmitPackets()+","+
                    statusPorta.getTempo()+
                    ");";
        stmt.executeUpdate(sql);  
    }
    
    
    /**
     * Return all StatusPort objects from database.
     * 
     * @return An Vector with all StatusPorts objects from database.
     * @throws SQLException
     */
    public Vector<StatusPort> getAll() throws SQLException {
        Vector<StatusPort> listStatusPort = new Vector<StatusPort>();
        ResultSet result;
        String sql = "SELECT * FROM ports";
        result = this.stmt.executeQuery(sql);
        while (result.next()) {
            StatusPort statusPort = new StatusPort();
            statusPort.setSwID(result.getInt("switchNumber"));
            statusPort.setTempo(result.getLong("tempo"));
            statusPort.setPortNumber((short)result.getInt("portNumber"));
            statusPort.setCollisions(result.getLong("collisions"));
            statusPort.setReceiveBytes(result.getLong("receiveBytes"));
            statusPort.setReceiveCRCErrors(result.getLong("receiveCRCErrors"));
            statusPort.setReceiveDropped(result.getLong("receiveDropped"));
            statusPort.setreceiveErrors(result.getLong("receiveErrors"));
            statusPort.setReceiveFrameErrors(result.getLong("receiveFrameErrors"));
            statusPort.setReceiveOverrunErrors(result.getLong("receiveOverrunErrors"));
            statusPort.setreceivePackets(result.getLong("receivePackets"));
            statusPort.setTransmitBytes(result.getLong("transmitBytes"));
            statusPort.setTransmitDropped(result.getLong("transmitDropped"));
            statusPort.setTransmitErrors(result.getLong("transmitErrors"));
            statusPort.setTransmitPackets(result.getLong("transmitPackets"));
            listStatusPort.add(statusPort);
        }
        
        return listStatusPort;
    }
    
}
