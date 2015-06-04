/**
 * This class is just used to group some variables/constants 
 * that are spread in all source code of Of-IDPS, 
 * and are constantly changed on Of-IDPS tests. 
 * Thus, instead alter this variable and constants in different 
 * parts of the code we can alter only here!
 * 
 * Then, this class is just to make our life more easy!
 * 
 *  @author Luiz Arthur Feitosa dos Santos
 *  @email luiz.arthur.feitosa.santos@gmail.com
 *  
 *  TODO - Integrated/join the time of alerts IDS and Flows analyzes?
 *  
 */
package net.beaconcontroller.tutorial;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.tools.FileManager;

public class CONFIG {
    
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    /*
     * Attributes to disable...
     * in the attributes to disable use 1 to disable or any other value to enable, like 0 (zero).
     */
    /*
     * Use to enable or disable ALL Of-IDPS architecture.
     */
    public static int DISABLE_OFIDPS=0;
    
    /*
     * This can disable the ability of Of-IDPF collect Openflows statistics 
     * messages from network elements, like switches.
     * If this is is equal to 1 (enable), this will too affect disable the
     * disableOfIDPS_UseOfAlerts because we won't have OpenFlow data to do
     * the analysis. 
     */
    //public static int disableOfIDPS_UseOfgetStatisticsFromNetwork=0;
    public static int DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK = 0;
    
    /*
     * Enable or disable the analysis of security threats based on OpenFlow
     * statistics, this depend that the
     * disableOfIDPS_UseOfgetStatisticsFromNetwork variable is enabled
     * (different of 1).
     * 
     * If just this variable is disabled and the
     * disableOfIDPS_UseOfgetStatisticsFromNetwork variable is enable, then, the
     * Of-IDPS will just collect Openflow statistics messages but won't use this
     * for reactions.
     * 
     * This is used, here and in the MemoryAttacks class.
     */
    //public static int disableOfIDPS_UseOfAlerts=0;
    public static int DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS = 0;
    
    /*
     *  Enable or disable the use of IDS message on the Of-IDPS
     *  
     *  This is used in the MemoryAttacks class.
     *  
     */
    //public static int disableOfIDPS_UseIDSAlerts=0;
    public static int DISABLE_OFIDPS_EXTERNAL_IDS = 0;
    
    
    
    // Memory Attacks variables/constants:
    /*
     * This time is the period of time to execute memory attacks thread.
     * In this thread is executed the mainly methods from MemorysAttacks class,
     * like for example, the time to construct security rules based on alerts security.  
     */
    public static int TIME_BETWEEN_RUN_MEMORY_ATTACKS = 3; // tempo criacao regras autonomicas

    /*
     * Period of time, in seconds, that an alert will be processed. This period
     * of time will be since the first time that it appear until the value in
     * this variables in seconds.
     */
    // TODO for SBRC tests we are changing this variable
    public static int TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY=30; // tempo memoria curta
    // TODO SBRC 2015 with times 10,30,60
    public static int TIME_TO_ALERTS_STAY_AT_SENSORIAL_MEMORY=TIME_BETWEEN_RUN_MEMORY_ATTACKS; // disable for now!
    public static int TIME_TO_ALERTS_STAY_AT_LONG_MEMORY=604800; // one year!
    /*
     * 600 - 10 minutes.
     * 1800 - 30 minutes.
     * 3600 - one hour.
     * 86400 - one day.
     * 604800 - one week.
     * 2629800 - one month.
     * 31557600 - one year.
     */

    
    // OpenFlow sensor variables/constants:    
    /*
     * This time is the period of time to execute OpenFlow sensor thread.
     * Get statistics information from OpenFlow elements (ie. switches).
     */
    public static int TIME_BETWEEN_RUN_SENSOR_OPENFLOW = 3; // tempo sensor

        
    
    
    
    // Analyzes flows variables/constants:
    /*
     * This time is the period of time to execute analyze flow thread.
     * In this thread is executed the mainly methods from AnalysisFlow class.
     */
    public static int TIME_BETWEEN_RUN_ANALYSIS_FLOW = TIME_BETWEEN_RUN_SENSOR_OPENFLOW;
    
    /*
     * Period of time that OpenFlow statics message will be retrieved 
     * from database. This is a kind of time of live. 
     */
    // TODO - the same from the most long memory attacks? should be the same variable?
    public static int TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB = TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY;

    // Disable Json output:
    /*
     * This is used to generate output that can be used to Web interface!
     * use false to enable and true to disable.
     */
    public static boolean DISABLE_JSON_OUTPUT = false;
    
    /**
     * Used to start some methods and attributes.
     */
    public static void startUp() {
        readConfigFromFile();
    }


    /**
     * Read configurations attributes from a file.
     */
    private static void readConfigFromFile() {
        FileManager fileManager = new FileManager("/etc/ofidps", "ofidps.conf");
        InputStream configurations = fileManager.readImputStreamFile();
        Properties prop = new Properties();
        try {
            prop.load(configurations);
            DISABLE_OFIDPS = propertieToInt(prop, "DISABLE_OFIDPS");
            DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK = propertieToInt(prop, "DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK");
            DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS = 
                    propertieToInt(prop, "DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS");
            DISABLE_OFIDPS_EXTERNAL_IDS = propertieToInt(prop, "DISABLE_OFIDPS_EXTERNAL_IDS");
            
            
            TIME_BETWEEN_RUN_MEMORY_ATTACKS = propertieToInt(prop, "TIME_BETWEEN_RUN_MEMORY_ATTACKS");
            TIME_TO_ALERTS_STAY_AT_SENSORIAL_MEMORY = propertieToInt(prop, "TIME_TO_ALERTS_STAY_AT_SENSORIAL_MEMORY");
            TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY = propertieToInt(prop, "TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY");
            TIME_TO_ALERTS_STAY_AT_LONG_MEMORY = propertieToInt(prop, "TIME_TO_ALERTS_STAY_AT_LONG_MEMORY");
            TIME_BETWEEN_RUN_SENSOR_OPENFLOW = propertieToInt(prop, "TIME_BETWEEN_RUN_SENSOR_OPENFLOW");
            TIME_BETWEEN_RUN_ANALYSIS_FLOW = propertieToInt(prop, "TIME_BETWEEN_RUN_ANALYSIS_FLOW");
            TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB = propertieToInt(prop, "TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB");
            DISABLE_JSON_OUTPUT = propertieToBoolean(prop, "DISABLE_JSON_OUTPUT");
        } catch (IOException e) {
            log.debug("ATTENTION!!! Error during config file processing...");
            e.printStackTrace();
        }
    }
    
    private static int propertieToInt(Properties prop, String key) {
        int value = Integer.parseInt(prop.getProperty(key));
        log.debug("CONFIG - {} = {}", key, value);
        return value;
    }
    
    private static Boolean propertieToBoolean(Properties prop, String key) {
        boolean value = Boolean.parseBoolean(prop.getProperty(key));
        log.debug("CONFIG - {} = {}", key, value);
        return value;
    }

}
