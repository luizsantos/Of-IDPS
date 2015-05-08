package net.beaconcontroller.tools;

import java.math.BigInteger;
import java.util.regex.Pattern;

import net.beaconcontroller.packet.IPv4;

public class IpAddress {
    
    /**
     * Convert integer IP to a BigInteger number.
     * 
     * 
     * @param address - integer IP.
     * @return - The IP in the BigInteger format.
     *  
     */
    public static BigInteger parseIntegerIPv4toBigInteger(int intAddress) {
        String address = IPv4.fromIPv4Address(intAddress);
        return parseStringIPv4toBigInteger(address);
    }
    
    /**
     * Convert IP to a BigInteger number.
     * 
     * 
     * @param address - in the octal string format, e.g. 127.0.0.1.
     * @return - The IP in the BigInteger format.
     * 
     * Inspired on solutions presented on:
     * http://stackoverflow.com/questions/12057853/how-to-convert-string-ip-numbers-to-integer-in-java
     * 
     */
    public static BigInteger parseStringIPv4toBigInteger(String address) {
        BigInteger bigIP = BigInteger.ZERO;
        // Iterate over each IP octet
        for(String stringOctetPart : address.split(Pattern.quote("."))) {
            // Shift the previously parsed bits over by 8 bits
            bigIP = bigIP.shiftLeft(8);
            // Set the low order bits to the current octet.
            BigInteger octet = new BigInteger(stringOctetPart);
            bigIP = bigIP.or(octet);           
        }
        return bigIP;
    }
    
    

}
