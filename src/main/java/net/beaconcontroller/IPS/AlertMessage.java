/** 
 *         Represents both, security alert messages and security rules that can
 *         be used to mitigate security threats. 
 *         
 *         The security alert message,
 *         represent an alert sent by a Intrusion Detection System - IDS, by the
 *         module of OpenFlow analysis of Of-IDPS, etc. Each alert represent,
 *         one network connection with sockets network, security alert
 *         description, etc. This can be stored to be compared with others alert
 *         messages or rules, and then, network flows related with this alerts
 *         can be blocked, have your bandwidth changed or be normally forwarded
 *         by the network. 
 *         
 *         The security rule too is represented by sockets
 *         network, security alert description, etc and can be applied by the
 *         Of-IDPS, like a Firewall rules in new or existing flows to be blocked,
 *         have your bandwidth changed or be normally forwarded by the network.
 *         
 *         @author Luiz Arthur Feitosa dos Santos
 *         @email luiz.arthur.feitosa.santos@gmail.com
 * 
 */


package net.beaconcontroller.IPS;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import net.OfIDPS.memoryAttacks.MemorysAttacks;
import net.beaconcontroller.packet.IPv4;
import net.beaconcontroller.tutorial.CONFIG;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;


public class AlertMessage {
    public static SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS"); // Datetime format required by database.
    private SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss.SSS"); // Used to format datetime.
    private Date tempo = new Date(); // Datatime of alert/rule
    private int life=1; // If >=0 rule is alive/valid.
    private boolean newRule = true; // If true, is a new rule!
    private int priorityAlert = Integer.MAX_VALUE; // Priority level, can be: low, medium, high.
    private String alertDescription = "none"; // Alert description.
    private int networkDestination = Integer.MAX_VALUE; // IP destination.
    private int networkSource = Integer.MAX_VALUE; // IP source.
    private int networkProtocol = Integer.MAX_VALUE; // Protocol field of datagram IP, normally: TCP, UDP or ICMP.
    private int transportDestination = Integer.MAX_VALUE; // Destination port.
    private int transportSource = Integer.MAX_VALUE; // Source port.
    private int supportApriori = Integer.MAX_VALUE; // Support applied to this by itemsets algorithm (http://en.wikipedia.org/wiki/Association_rule_learning).
    
    // TEST
    private int packetsMatchInOfControllerPerHop=0; //packets that match with this rule/alert on the controller until the last memory attacks execution.
    private int averagePacketsMatchInOfControllerPerHop=0;
    private int totalPacketsMatchInOfController=0; //All packets that match with this rule/alert on the controller
   
    /*
     * Types of priority levels:
     */
    public static final int NORMAL_PACKET = 4; // Represents WITHOUT priority security level - represents a NORMAL PACKET/flow.
    public static final int ALERT_PRIORITY_LOW = 3; // Represents LOW priority security level.
    public static final int ALERT_PRIORITY_MEDIUM = 2; // Represents MEDIUM priority security level.
    public static final int ALERT_PRIORITY_HIGH = 1; // Represents HIGH priority security level.
    
    
    
    public static final int MAX_LIVE = 10; // Represents the maximum value of alert/rule life.

    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class); // for log

    public void setNewRule() {
        this.newRule=true;
    }
    
    public void disableNewRule() {
        this.newRule=false;
    }
    
    public boolean verifyNewRule() {
        if(newRule) {
            return true; // this rule is new!
        }
        return false; // this rule is old! 
    }
    
    /**
     * verify if rule/alert is alive or not.
     * @return true - live, false is dead.
     */
    public boolean verifyLife() {
        if(this.life<0) {
            return false; // rule,alert isn't alive.
        }
        return true; // rule,alert is alive.
    }
    
    /**
     * To increase the count of live! This count can reach at maximum up to
     * MAX_LIVE constant value.
     */
    public void increaseLife() {
        if (this.life < MAX_LIVE) {
            this.life++;
        } else {
            this.life = MAX_LIVE;
        }
    }
    
    /**
     * To increase the count of live! This count can reach at maximum up to
     * MAX_LIVE constant value.
     * @param numberToIncrease - number to be added in to life count!
     */
    public void increaseLife(int numberToIncrease) {
        if (numberToIncrease < MAX_LIVE) {
            this.life = this.life+numberToIncrease;
        } else {
            this.life = MAX_LIVE;
        }
    }
    
    /**
     * Decrease the life of rule/alert.
     */
    public void decreaseLife() {
        this.life--;
    }
    
    /**
     * The rule live will be set on 2, because after this the
     * life count already will be decreased.
     */
    public void setLife() {
        this.life=3;
    }
    
    public int getLife() {
        return this.life;
    }
    
    public Date getTempo() {
        return tempo;
    }

    public void setTempo(Date tempo) {
        this.tempo = tempo;
    }
    
    public String getTempoStringBD() {
        return formatterDB.format(this.tempo).toString();
    }
    
    /**
     * Verify alert time
     * 
     *  @return true if the alert is valid or false if this alert have your time expired.
     */
    public boolean verifyIfAlertTimeExpired() {
        Calendar currentDateTime = Calendar.getInstance();
        /*
         * We use a margin of 1.5 seconds to avoid remove premature rules.
         */
        currentDateTime.add(Calendar.MILLISECOND, -1500);
        if(this.tempo.before(currentDateTime.getTime())) {
            // Alert time it's valid.
            return true;
        } else {
            // This alert have your time expired.
            return false;
        }
    }
    
    /**
     * Increase alert time.
     */
    public void increaseAlertTime() {
        Calendar currentDateTimeIncreased =  Calendar.getInstance();
        currentDateTimeIncreased.add(Calendar.SECOND, MemorysAttacks.timeToAlertsStayAtShortMemory);
        log.debug("This alert had your time increased in {} seconds ({})",
                MemorysAttacks.timeToAlertsStayAtShortMemory, currentDateTimeIncreased.getTime());
        this.tempo = currentDateTimeIncreased.getTime();
    }
    
    /**
     * Set time with current time on the system
     */
    public void setTempo() {
        Date currentDateTime =  new Date();
        this.tempo = currentDateTime;
    }
    
    /**
     * Convert a string to date, the string must be passed in format:
     *              MM/dd-HH:mm:ss.SSS
     * where: 
     *  MM - month
     *  dd - day
     *  HH - hour
     *  mm - minutes
     *  ss - seconds
     *  SSS - milliseconds
     *
     * Attention don't pass the year, this will be set up by the controller.
     * 
     * @param time - MM/dd-HH:mm:ss.SSS
     */
    public void setTempo(String alertDate) {
        // Get year to be used on time alert
        DateFormat yearDateFormat = new SimpleDateFormat("yyyy");
        Date year = new Date();
        String yearString = yearDateFormat.format(year);
        Date date = new Date();
        // Convert
        try {
            date = formatter.parse(yearString+"/"+alertDate);
        } catch (ParseException e) {
            log.debug("ATTENTION!!!, problems with time/date on alert message on MensagemAlerta class.");
            e.printStackTrace();
        }        
        this.tempo = date;
    }

    public int getPriorityAlert() {
        return priorityAlert;
    }

    public void setPriorityAlert(int priorityAlert) {
        this.priorityAlert = priorityAlert;
    }

    public String getAlertDescription() {
        return alertDescription;
    }

    public void setAlertDescription(String alertDescription) {
        this.alertDescription = alertDescription;
    }

    public int getNetworkDestination() {
        return networkDestination;
    }

    public void setNetworkDestination(int networkDestination) {
        this.networkDestination = networkDestination;
    }

    public void setNetworkDestination(String networkDestination) {
        try {
            // TODO - provisionally treat IPv6 - handle this better after!
            this.networkDestination = IPv4.toIPv4Address(networkDestination);
        } catch (Exception e) {
            this.networkDestination = IPv4.toIPv4Address("6.6.6.6");
        }
    }

    public int getNetworkSource() {
        return networkSource;
    }

    public void setNetworkSource(int networkSource) {
        this.networkSource = networkSource;
    }

    public void setNetworkSource(String networkSource) {
        try {
            this.networkSource = IPv4.toIPv4Address(networkSource);
        } catch (Exception e) {
         // TODO - provisionally treat IPv6 - handle this better after!
            this.networkSource = IPv4.toIPv4Address("6.6.6.6");
        }
    }

    public int getNetworkProtocol() {
        return networkProtocol;
    }

    public void setNetworkProtocol(int networkProtocol) {
        this.networkProtocol = networkProtocol;
    }

    public int getTransportDestination() {
        return transportDestination;
    }

    public void setTransportDestination(int transportDestination) {
        this.transportDestination = transportDestination;
    }

    public int getTransportSource() {
        return transportSource;
    }

    public void setTransportSource(int transportSource) {
        this.transportSource = transportSource;
    }
    
    

    public int getSupportApriori() {
        return supportApriori;
    }

    public void setSupportApriori(int supportApriori) {
        this.supportApriori = supportApriori;
    }
    
    /**
     * Get the total of packet that combine with this 
     * rules since of the last hop.
     * @return number of packets
     */
    public int getPacketsMatchInOfControllerPerHop() {
        return packetsMatchInOfControllerPerHop;
    }
    
    /**
     * Get the average of packets that combine with this 
     * rules since of the last hop.
     * @return number average packets
     */
    public int getAveragePacketsMatchInOfControllerPerHop() {
        return averagePacketsMatchInOfControllerPerHop;
    }
    
    /**
     * Increase the count controller to the number of packets 
     * that are incoming in the OpenFlow controller and that 
     * matches with this rule/alert - this can be used to control 
     * if the rule yet is useful.
     */
    public void increasePacketsMatchInOfControllerPerHop() {
        this.packetsMatchInOfControllerPerHop++;
        this.totalPacketsMatchInOfController++;
    }
    
    /**
     * Verify if there are packets arriving in the controller and that 
     * combine with this rule, and if this packets still represents 
     * risk to the system. Case yes maintain the rule.
     */
    public void verifyAndUpdatePacketsMatchInOfControllerPerHop(){
        /*
         * averagePacketsMatch attribute store the average of packets 
         * that match with this rules since of last time that the thread 
         * to construct memory attacks was executed 
         * (this.packetsMatchInOfController/CONFIG.TIME_BETWEEN_RUN_MEMORY_ATTACKS)!
         */
        this.averagePacketsMatchInOfControllerPerHop = (this.packetsMatchInOfControllerPerHop/CONFIG.TIME_BETWEEN_RUN_MEMORY_ATTACKS);
        /*
         * Test to detect if thus rule still avoid an attack!
         * 
         * TODO - We should use some statistic to determine the 
         * value of packets arrive that represents an attack! 
         * But different attacks will have different metrics, 
         * DDoS for example will have many packets but we can have 
         * attacks where just one packet represent a risk to the 
         * system... verify!
         */
        if(this.averagePacketsMatchInOfControllerPerHop>50) {
            this.printMsgAlert();
            log.debug("This rule will be maintained because {} ({}/{}) packets combine with this.", 
                    this.averagePacketsMatchInOfControllerPerHop, this.packetsMatchInOfControllerPerHop, CONFIG.TIME_BETWEEN_RUN_MEMORY_ATTACKS);
            this.setLife();
        }
        this.packetsMatchInOfControllerPerHop=0;
    }
    
    /**
     * Get the total of packet that combine with this rules since that this rule was created.
     * @return total of packets.
     */
    public int getTotalPacketsMatchInOfController() {
        return totalPacketsMatchInOfController;
    }
    
    /**
     * Will return the average of packets per seconds since that this rule was created.
     * @return packets per seconds that combine with this rules since this be created.
     */
    public int getAverageOfTotalPacketsMatchInOfControllerPerSeconds() {
        Date currentDate = Calendar.getInstance().getTime();
        long timeDifference = currentDate.getTime() - this.tempo.getTime();
        long differenceInSeconds = timeDifference/1000%60;
        if(differenceInSeconds>0) {
            return (int) (totalPacketsMatchInOfController/differenceInSeconds);
        }
        return 0;
    }

    /**
     * Get a string that contain network socket - this can be used to represent/identify the connection
     * 
     * @return key - that is a concatenated string formed by: Network Source +
     *         Network Destination + Network Protocol + Source Transport +
     *         Destination Transport.
     */
    public String getKeyFromNetworkSocket() {
        return Integer.toString(this.getNetworkSource())
                + Integer.toString(this.getNetworkDestination())
                + Integer.toString(this.getNetworkProtocol())
                + Integer.toString(this.getTransportSource())
                + Integer.toString(this.getTransportDestination());
    }

    /**
     * Show/print the alert message
     * In order: Network Source,Transport Source,Network Destination,Transport Destination,Network Protocol,
     * alert priority, alert description, algorithm itemsets support.
     */
    public void printMsgAlert() {
        log.debug(convertToAnyIfNecessary(this.getNetworkSource()) + ":"
                + convertToAnyIfNecessary(this.getTransportSource()) + "->"
                + convertToAnyIfNecessary(this.getNetworkDestination()) + ":"
                + convertToAnyIfNecessary(this.getTransportDestination()) + " (" 
                + convertToAnyIfNecessary(this.getNetworkProtocol()) + ") priority: <"
                + convertToAnyIfNecessary(this.getPriorityAlert()) + "> desc: "
                + this.getAlertDescription() + " support: ["
                + this.getSupportApriori() + "]"+
                " rule life: "+ +this.getLife() +
                " date: " + formatter.format(this.getTempo()));
    }
    
    /**
     * Get a string that represent the alert/rule message.
     * In order: Security priority, Network Source,Transport Source,Network Destination,Transport Destination,Network Protocol,
     * algorithm itemsets support, alert description, alert/rule life, alert/rule datetime.
     */
    public String getStringMsgAlert() {
        return "priority: " + convertToSecurityPriorityString(this.getPriorityAlert()) + "\t" 
                + convertToAnyIfNecessary(this.getNetworkSource()) + ":"
                + convertToAnyIfNecessary(this.getTransportSource()) + "->"
                + convertToAnyIfNecessary(this.getNetworkDestination()) + ":"
                + convertToAnyIfNecessary(this.getTransportDestination()) + " (" 
                + convertToAnyIfNecessary(this.getNetworkProtocol()) + ")\tsupport: "
                + this.getSupportApriori() + " sec desc: "
                + this.getAlertDescription() + " - "+
                " rule life: "+ +this.getLife() +
                " date: " + formatter.format(this.getTempo());
    }
    
    /**
     * Get a string that represent the alert/rule message.
     * In order: Security priority, Network Source,Transport Source,Network Destination,Transport Destination,Network Protocol,
     * algorithm itemsets support, alert description, alert/rule life, alert/rule datetime.
     */
    public String getJsonMsgAlert() {
        JSONObject alertJson = new JSONObject();
        alertJson.put("priorityAlert", convertToSecurityPriorityString(this.getPriorityAlert()));
        alertJson.put("networkSource", convertIPv4ToAnyIfNecessary(this.getNetworkSource()));
        alertJson.put("networkDestination", convertIPv4ToAnyIfNecessary(this.getNetworkDestination()));
        alertJson.put("networkProtocol", convertProtocolToAnyIfNecessary(this.getNetworkProtocol()));
        alertJson.put("transportSource", convertToAnyIfNecessary(this.getTransportSource()));
        alertJson.put("transportDestination", convertToAnyIfNecessary(this.getTransportDestination()));
        alertJson.put("supportApriori", this.getSupportApriori());
        alertJson.put("alertDescription", this.getAlertDescription());
        alertJson.put("life", this.getLife());
        alertJson.put("averagePacketsMatchInOfControllerPerHop", this.getAveragePacketsMatchInOfControllerPerHop());
        alertJson.put("totalPacketsMatchInOfController", this.getTotalPacketsMatchInOfController());
        alertJson.put("averageOfTotalPacketsMatchInOfControllerPerSeconds", this.getAverageOfTotalPacketsMatchInOfControllerPerSeconds());
        alertJson.put("tempo", formatter.format(this.getTempo()));
        return alertJson.toJSONString();
    }
    
    /**
     * Print life in seconds
     */
    public void printLifeInSeconds() {
        log.debug("rule/alert time live in seconds: ~"+ this.getLife()*MemorysAttacks.TIME_TO_WAIT);
    }
    
    /**
     * Print * (any) instead of the value that represent Integer.MAX_VALUE
     * @param - value of netSource, transportDestination, etc..
     * @return - * (any) or the value 
     */
    public String convertToAnyIfNecessary(int value) {
        if(value==Integer.MAX_VALUE) {
            return "*";
        } 
        return Integer.toString(value);
    }
    
    /**
     * Print * (any) instead of the value that represent Integer.MAX_VALUE
     * and convert protocol integer value to the protocol name.
     * @param - value of netSource, transportDestination, etc..
     * @return - * (any) or the value 
     */
    public String convertProtocolToAnyIfNecessary(int value) {
        if(value==Integer.MAX_VALUE) {
            return "*";
        } 
        switch (value) {
            case 1:
                return "ICMP";
            case 6:
                return "TCP";
            case 17:
                return "UDP";
        }
        return Integer.toString(value);
    }
    
    /**
     * Print * (any) instead of the value that represent Integer.MAX_VALUE
     * and convert the integer IP value to common IP value X.X.X.X.
     * @param - value of netSource, transportDestination, etc..
     * @return - * (any) or the value 
     */
    public String convertIPv4ToAnyIfNecessary(int value) {
        if(value==Integer.MAX_VALUE) {
            return "*";
        } 
        return IPv4.fromIPv4Address(value);
    }
    
    /**
     * Print security priority instead of the value
     * @param - value security priority
     * @return - security priority string 
     */
    public String convertToSecurityPriorityString(int value) {
        switch (value) {
            case NORMAL_PACKET:
                return "NO";
            case ALERT_PRIORITY_LOW:
                return "LOW";
            case ALERT_PRIORITY_MEDIUM:
                return "MEDIUM";
            case ALERT_PRIORITY_HIGH:
                return "HIGH";
            default:
                return "UNKNOWN";
        }
    }
    

}
