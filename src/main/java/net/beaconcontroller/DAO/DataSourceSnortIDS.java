/**
 * Used to make postgres database connection and get IDS Snort alerts.
 * 
 * The database access is made using a database polling connection technique 
 * (http://syntx.io/configuring-c3p0-connection-pooling-with-jdbc/), 
 * this is necessary because Of-IDPS can make a lot of database access to read 
 * or write OpenFlow statistics, IDS alerts, etc, and this can overload the 
 * database, and polling connection technique can prevent this problem.
 *
 * If you don't have the database installed, you will need:
 *  1. Install and configure a postgres server (remember that you must grant/allow 
 *          the database access from network);
 *  2. Use the https://github.com/firnsy/barnyard2/blob/master/doc/README.database tutorial
 *  to install and configure the database.
 *  
 *  @author Luiz Arthur Feitosa dos Santos
 *  @email luiz.arthur.feitosa.santos@gmail.com
 */
package net.beaconcontroller.DAO;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.SQLException;

import com.mchange.v2.c3p0.ComboPooledDataSource;

import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DataSourceSnortIDS {
    // Database configuration variables.
    //public static final String URL = "jdbc:mysql://localhost:3306/OF_IDPS";
    public static final String URL = "jdbc:postgresql://localhost:5432/snort";
    //public static final String USERNAME = "root";
    public static final String USERNAME = "snort";
    public static final String PASSWORD = "123mudar";
    //public static final String DRIVER_CLASS = "com.mysql.jdbc.Driver";
    public static final String DRIVER_CLASS = "org.postgresql.Driver";
    
    private static DataSourceSnortIDS datasource;
    private ComboPooledDataSource cpds;
    
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    /**
     * Used to configure database and connection polling.
     * 
     * @throws PropertyVetoException
     */
    private DataSourceSnortIDS() throws PropertyVetoException {
        // Setup database.
        cpds = new ComboPooledDataSource();
        cpds.setDriverClass(DRIVER_CLASS);
        cpds.setJdbcUrl(URL);
        cpds.setUser(USERNAME);
        cpds.setPassword(PASSWORD);
        // Setup connection polling.
        cpds.setMinPoolSize(3);
        cpds.setAcquireIncrement(5);
        cpds.setMaxPoolSize(20);
        cpds.setMaxStatements(180);
    }
    
    /**
     * Get database instance with connection polling.
     * 
     * @return datasource.
     * @throws PropertyVetoException.
     */
    public static DataSourceSnortIDS getInstance() throws PropertyVetoException {
        if(datasource==null) {
            datasource = new DataSourceSnortIDS(); 
            return datasource;
        } else {
            return datasource;
        }
        
    }
    
    /**
     * Get database connection.
     * 
     * @return Database connection.
     * @throws SQLException
     */
    public Connection getConnection() throws SQLException {
       return this.cpds.getConnection();
        
    }

}
