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

public class CONFIG {
    
    // Memory Attacks variables/constants:
    /*
     * This time is the period of time to execute memory attacks thread.
     * In this thread is executed the mainly methods from MemorysAttacks class,
     * like for example, the time to construct security rules based on alerts security.  
     */
    public static final int TIME_BETWEEN_RUN_MEMORY_ATTACKS = 3; // tempo criacao regras autonomicas

    /*
     * Period of time, in seconds, that an alert will be processed. This period
     * of time will be since the first time that it appear until the value in
     * this variables in seconds.
     */
    // TODO for SBRC tests we are changing this variable
    public static int TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY=30; // tempo memoria curta
    // TODO SBRC 2015 with times 10,30,60
    public static int TIME_TO_ALERTS_STAY_AT_SENSORIAL_MEMORY=TIME_BETWEEN_RUN_MEMORY_ATTACKS; // disable for now!
    public static int TIME_TO_ALERTS_STAY_AT_LONG_MEMOY=604800; // one year!
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
    public static final int TIME_BETWEEN_RUN_SENSOR_OPENFLOW = 3; // tempo sensor

        
    
    
    
    // Analyzes flows variables/constants:
    /*
     * This time is the period of time to execute analyze flow thread.
     * In this thread is executed the mainly methods from AnalysisFlow class.
     */
    public static final int TIME_BETWEEN_RUN_ANALYSIS_FLOW = TIME_BETWEEN_RUN_SENSOR_OPENFLOW;
    
    /*
     * Period of time that OpenFlow statics message will be retrieved 
     * from database. This is a kind of time of live. 
     */
    // TODO - the same from the most long memory attacks? should be the same variable?
    public static final int TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB = TIME_TO_ALERTS_STAY_AT_SHORT_MEMORY;

    // Disable Json output:
    /*
     * This is used to generate output that can be used to Web interface!
     * use false to enable and true to disable.
     */
    public static final boolean DISABLE_JSON_OUTPUT = false;

}
