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
    
    /*
     * Attributes used to disable or enable sensorial, short, and long (bad/good) memory.
     */    
    // Disable sensorial memory
    //protected static int disableSensorialMemory=0;
    public static int DISABLE_MEMORY_SENSORIAL = 0;
    
    // Disable short-term memory
    //protected static int disableShortMemory=0;
    public static int DISABLE_MEMORY_SHORT = 0;
    
    // To disable long-term bad memory.
    //public static int disableLongBadMemory=0;
    public static int DISABLE_MEMORY_LONG_BAD = 0;
    
    // To disable long-term good memory.
    //public static int disableLongGoodMemory=0;
    public static int DISABLE_MEMORY_LONG_GOOD = 0;
    
    // Disable different forms of security containment for different levels of security alerts.
    /*
     * In the Of-IDPS, packets related with: 
     *  - Low security level alert, will has your bandwidth softly reduced;
     *  - Medium security level alert, will has your bandwidth severely reduced;
     *  - High security level alert, will has your packets blocked.
     *  
     *  ATTENTION - If we disable this control ALL PACKETS related with alerts will be BLOCKED.
     */
    public static int DISABLE_DIFFERENT_SECURITY_CONTAINMENT_FOR_DIFFERENT_ALERTS_LEVELS=0;
    
    // Attribute that deals with the order of the rules to be analyzed and applied in the Of-IDPS.
    /*
     * Order to be read/analyzed the memories rules:
     *      1       |     2     |     3     |   4
     * -------------|-----------|-----------|----------
     * longGood     | sensorial |sensorial  | sensorial
     * sensorial    | longGood  |short      | short
     * short        | short     |longGood   | longBad
     * longBad      | longBad   |longBad    |
     * 
     * See MemorysAttack class.
     */
    public static int MEMORY_ORDER_TO_BE_APPLIED_IN_THE_OFIDPS = 3;
    
    //Method to recover remembrances to long memory.
    /*
     * You must choose:
     * 1 - Get all remembrances - this can consume a lot of the machine process.
     * 2 - Get remembrances using a limit to recovery the database register, example get the last 10.000 registers.
     * 3 - Get remembrances using a limit but get the registers randomly.
     * 4 - Get remembrances using a limit but get the registers randomly and using a statistic threshold based on the amount of existent registers in database to generate reliable samples.
     * 5 - Get remembrances up to seconds ago.
     * 6 - Get remembrances up to seconds ago but get the registers randomly.
     * 7 - Get remembrances up to seconds ago but get the registers randomly and using a statistic threshold based on the amount of existent registers in database to generate reliable samples.
     * See LongTermMemory class.
     */
    //public static int methodToRecoverRemembrancesToLongMemory = 7 ;
    public static int MEMORY_LONG_METHOD_RECOVER_REMEMBRANCES = 7;
    
    // Max number of registers to be recovered from database and be processed by long memories to form good/bad remembrances.
    //public static int limit_to_recover_databaseFlows=10000;
    public static int MEMORY_LONG_METHOD_RECOVER_REMEMBRANCES_LIMIT_TO_RECOVER_FROM_DB=10000;
    
    
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
    
    // Of-IDPS DATABASE
    // Database host.
    public static String DB_OFIDPS_HOST="localhost";
    // Database network port.
    public static String DB_OFIDPS_PORT="5432";
    // Database name.
    public static String DB_OFIDPS_NAME="ofidps";
    // Database user.
    public static String DB_OFIDPS_USER="ofidps";
    // Database password.
    public static String DB_OFIDPS_PASSWORD="123mudar";
    
    // Snort DATABASE
    // Database host.
    public static String DB_SNORT_HOST="localhost";
    // Database network port.
    public static String DB_SNORT_PORT="5432";
    // Database name.
    public static String DB_SNORT_NAME="snort";
    // Database user.
    public static String DB_SNORT_USER="snort";
    // Database password.
    public static String DB_SNORT_PASSWORD="123mudar"; 
    
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
            DISABLE_MEMORY_SENSORIAL = propertieToInt(prop, "DISABLE_MEMORY_SENSORIAL");
            DISABLE_MEMORY_SHORT = propertieToInt(prop, "DISABLE_MEMORY_SHORT");
            DISABLE_MEMORY_LONG_BAD = propertieToInt(prop, "DISABLE_MEMORY_LONG_BAD");
            DISABLE_MEMORY_LONG_GOOD = propertieToInt(prop, "DISABLE_MEMORY_LONG_GOOD");
            
            DISABLE_DIFFERENT_SECURITY_CONTAINMENT_FOR_DIFFERENT_ALERTS_LEVELS = propertieToInt(prop,
                    "DISABLE_DIFFERENT_SECURITY_CONTAINMENT_FOR_DIFFERENT_ALERTS_LEVELS");
            
            MEMORY_ORDER_TO_BE_APPLIED_IN_THE_OFIDPS = propertieToInt(prop, "MEMORY_ORDER_TO_BE_APPLIED_IN_THE_OFIDPS");
            MEMORY_LONG_METHOD_RECOVER_REMEMBRANCES = propertieToInt(prop, "MEMORY_LONG_METHOD_RECOVER_REMEMBRANCES");
            MEMORY_LONG_METHOD_RECOVER_REMEMBRANCES_LIMIT_TO_RECOVER_FROM_DB = propertieToInt(prop, 
                    "MEMORY_LONG_METHOD_RECOVER_REMEMBRANCES_LIMIT_TO_RECOVER_FROM_DB");
                        
            TIME_BETWEEN_RUN_MEMORY_ATTACKS = propertieToInt(prop, "TIME_BETWEEN_RUN_MEMORY_ATTACKS");
            TIME_TO_ALERTS_STAY_AT_SENSORIAL_MEMORY = propertieToInt(prop, "TIME_TO_ALERTS_STAY_AT_SENSORIAL_MEMORY");
            TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY = propertieToInt(prop, "TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY");
            TIME_TO_ALERTS_STAY_AT_LONG_MEMORY = propertieToInt(prop, "TIME_TO_ALERTS_STAY_AT_LONG_MEMORY");
            TIME_BETWEEN_RUN_SENSOR_OPENFLOW = propertieToInt(prop, "TIME_BETWEEN_RUN_SENSOR_OPENFLOW");
            TIME_BETWEEN_RUN_ANALYSIS_FLOW = propertieToInt(prop, "TIME_BETWEEN_RUN_ANALYSIS_FLOW");
            TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB = propertieToInt(prop, "TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB");
            DISABLE_JSON_OUTPUT = propertieToBoolean(prop, "DISABLE_JSON_OUTPUT");
            DB_OFIDPS_HOST = propertieToString(prop, "DB_OFIDPS_HOST");
            DB_OFIDPS_PORT = propertieToString(prop, "DB_OFIDPS_PORT");
            DB_OFIDPS_NAME = propertieToString(prop, "DB_OFIDPS_NAME");
            DB_OFIDPS_USER = propertieToString(prop, "DB_OFIDPS_USER");
            DB_OFIDPS_PASSWORD = propertieToString(prop, "DB_OFIDPS_PASSWORD");
            DB_SNORT_HOST = propertieToString(prop, "DB_SNORT_HOST");
            DB_SNORT_PORT = propertieToString(prop, "DB_SNORT_PORT");
            DB_SNORT_NAME = propertieToString(prop, "DB_SNORT_NAME");
            DB_SNORT_USER = propertieToString(prop, "DB_SNORT_USER");
            DB_SNORT_PASSWORD = propertieToString(prop, "DB_SNORT_PASSWORD");
            
            

            
        } catch (IOException e) {
            log.debug("ATTENTION!!! Error during config file processing...");
            e.printStackTrace();
        }
    }
    
    private static String propertieToString(Properties prop, String key) {
        String value = prop.getProperty(key);
        if(key.equalsIgnoreCase("DB_OFIDPS_PASSWORD") || key.equals("DB_SNORT_PASSWORD")) {
            log.debug("CONFIG - {} = *****", key);
        } else {
            log.debug("CONFIG - {} = {}", key, value);
        }
        return value;
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
