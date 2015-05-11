/*
 * Class that help with some network port tasks, like conversions.
 * 
 * Short port number are used in Beacon OpenFlow Controller. 
 * But, many others software use a integer number to represent network ports, like Snort IDS.
 */
package net.beaconcontroller.tools;

import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TransportPorts {
    
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class); // for log
    
    /**
     * Convert a short port number to a integer port number. 
     * @param port (-32768 until 32767)
     * @return Integer port number (0 until 65535)
     * 
     * Short port number are used in Beacon OpenFlow Controller. 
     * But, many others software use a integer number to represent network ports, like Snort IDS.
     *  
     */
    public static int convertShortPortToIntegerPort(short port) {
        return port & 0xFFFF;
    }
    
    /**
     * Convert an integer value, but with a short port number representation, to a integer port number. 
     * @param port (-32768 until 32767)
     * @return Integer port number (0 until 65535)
     * 
     * Short port number are used in Beacon OpenFlow Controller.
     * But, many others software use a integer number to represent network ports, like Snort IDS.
     *  
     */
    public static int convertIntegerShortPortToIntegerPort(int port) {
     // A caution to maintain the wildcard ANY, used in memory attack rules. 
        if (port==Integer.MAX_VALUE) {
            return port;
        } else {
            return port & 0xFFFF;
        }
    }
    
    
    
    /**
     * Convert the integer number port (0 until 65535) to a 
     * short number representation (-32768 until 32767), but yet in 
     * an integer form!
     * 
     * @param port - integer port (0 until 65535).
     * @return Integer port number, however in a short number representation but yet in a integer (-32768 until 32767).
     */
    public static int convertIntegerPortToIntegerShortValue(int port) {
        // A caution to maintain the wildcard ANY, used in memory attack rules. 
        if (port==Integer.MAX_VALUE) {
            return port;
        } else {
            short shortPort = (short) port;
            return (int) shortPort;
        }
    }
    
    /**
     * Convert an integer number port (0 until 65535) to a 
     * short number port (-32768 until 32767)!
     * 
     * @param port - integer port (0 until 65535).
     * @return Integer port number, however in a short number representation but yet in a integer (-32768 until 32767).
     */
    public static short convertIntegerPortValueToShort(int port) {
        // A caution to maintain the wildcard ANY, used in memory attack rules.
        if (port==Integer.MAX_VALUE) {
            log.debug("\n\nATTENTION!!!! It's impossible to convert integer port number to short number - Because it's is a wildcard - Integer.MAX_NUMBER.\n\n"); 
            return 0;
        } else {
            return (short) port;
        }
    }
    

}
