/**
 * Process alerts from IDS - Snort!
 * 
 * Now this class represents the IDS SENSOR and the main method is the getAlertsFromSnortIDS! 
 * 
 * TODO - Now, we aren't using more threads ability, then we can remove this. Correct? (verify)  
 * 
 *  @author Luiz Arthur Feitosa dos Santos
 *  @email luiz.arthur.feitosa.santos@gmail.com
 * 
 */

package net.beaconcontroller.IPS;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import net.OfIDPS.memoryAttacks.MemorysAttacks;
import net.beaconcontroller.DAO.SnortAlertMessageDAO;
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.packet.IPv4;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tools.FileManager;
import net.beaconcontroller.tools.ProtocolsNumbers;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class IntrusionPreventionSystem extends Thread implements
        IOFMessageListener {

    protected IBeaconProvider beaconProvider;
    // command to share sshfs mininet@192.168.1.200:/home/mininet/alertas/ /mnt/armazem/openflow/tmp/alertas/
    private String directoryName = "/mnt/armazem/openflow/tmp/alertas/";
    private String fileName = "formatted_log.csv";

    // TODO - list is the better choice?
    List<AlertMessage> listOfAlertMessages = new java.util.Vector<AlertMessage>();

    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);

    /**
     * Start thread to recovery alerts from IDS.
     */
//    public void run() {
//        log.debug("Starts thread to get alerts from IDS");
//        log.debug("STOP thread to get alerts from IDS");
//    }

    public void startUp(IBeaconProvider bP) {
        log.debug("Starts object to get alerts from IDS");
        this.beaconProvider = bP;
        beaconProvider.addOFMessageListener(OFType.STATS_REPLY, this);
    }

    public int verifyFlow(OFPacketIn pi) {

        OFMatch packetIn = OFMatch.load(pi.getPacketData(),
                pi.getInPort());
        
        for (AlertMessage alertMsg : listOfAlertMessages) {
            /*
             * Match variable is 0 if packet in don't combine with no rule! And greater than 0 if combine! 
             */
            int match = 0; 
            // mostraMensagemAlertaEPacoteDeEntrada(pacoteEntrando, m);
            if (alertMsg.getNetworkSource() == packetIn.getNetworkSource())
                match++;
            if (alertMsg.getNetworkDestination() == packetIn.getNetworkDestination())
                match++;
            if (alertMsg.getNetworkProtocol() == packetIn.getNetworkProtocol())
                match++;

            // If packet is ICMP we not verify the ports!
            if (alertMsg.getNetworkProtocol() == ProtocolsNumbers.ICMP) {
                // TODO - Is required do this to another protocols? It's correct? 
                // log.debug("Match={}", match);
                if (match >= 3) {
                     //printAlertMessageAndPacketIn(packetIn, alertMessage);
                    return alertMsg.getPriorityAlert();
                    // return 1; // Block the packet!
                }
            }

            // Verify ports if packet in is TCP or UDP.
            if (alertMsg.getNetworkProtocol() == ProtocolsNumbers.TCP
                    || alertMsg.getNetworkProtocol() == ProtocolsNumbers.UDP) {

                if (alertMsg.getTransportSource() == packetIn
                        .getTransportSource()
                        || alertMsg.getTransportDestination() == packetIn
                                .getTransportDestination())
                    match++;
                // log.debug("Match={}", match);
                if (match >= 4) {
                    //printAlertMessageAndPacketIn(packetIn, alertMessage);
                    return alertMsg.getPriorityAlert();
                    // return 1; // Block the packet!
                }
            }
        }
        return AlertMessage.NORMAL_PACKET;
    }
    
    
    /**
     * Gets alerts from Snort database IDS.
     * 
     * @return list of alerts from Snort in the format of Of-IDPS AlertMessages.
     * 
     */
//    public List<AlertMessage> getAlertsFromSnortIDS(String stringWhoCalled) {
//        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
//        //List<AlertMessage> listOfSnortAlerts = snortAlertMessageDAO.getSnortAlerts();
//        List<AlertMessage> listOfSnortAlerts = snortAlertMessageDAO.getSnortAlertsUpToSecondsAgo(MemorysAttacks.timeToAlertsStayAtShortMemory, stringWhoCalled);
//        return listOfSnortAlerts;  
//    }
    
    /**
     * Gets alerts from Snort database IDS using a period of time 
     * (from current datetime minus an amount of seconds).
     * 
     * @param timeInSeconds - amount of time in seconds to be decreased from the current datetime system.
     * @return list of alerts from Snort in the format of Of-IDPS AlertMessages.
     * 
     */
    public List<AlertMessage> getAlertsFromSnortIDS(int timeInSeconds, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        //List<AlertMessage> listOfSnortAlerts = snortAlertMessageDAO.getSnortAlerts();
        List<AlertMessage> listOfSnortAlerts = snortAlertMessageDAO.getList_SnortAlerts_UpToSecondsAgo(timeInSeconds, stringWhoCalled);
        return listOfSnortAlerts;  
    }
    
    /**
     * Get an itemset algorithm string of Snort alerts up to seconds ago from dabatase.
     * 
     * @param timeInSeconds - amount of time in seconds to be decreased from the current datetime system.
     * @return - Itemset string of Snort alerts.
     * 
     */
    public String getItemsetsString_SnortAlerts_upToSecondsAgo(int timeInSeconds, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        //return snortAlertMessageDAO.getSnortAlertsUpToSecondsAgo(timeInSeconds, stringWhoCalled);
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_3_UpToSecondsAgo(
                timeInSeconds, 
                stringWhoCalled);
    }
    
    // 1
    /**
     * Get itemset string from all normal flows.
     * @param - stringWhoCalled - Just a commentary to identification. 
     * @return - Itemset string of Snort alerts.
     */
    public String getItemsetsString_SnortAlerts_1_allFlows(String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_1_All(stringWhoCalled);
    }
    
    // 2
    /**
     * Get last Snort alerts using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of Snort Alerts.
     */
    public String getItemsetsString_SnortAlerts_2_lastUsingLimit(int limit, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_2_lastUsingLimit(limit, stringWhoCalled);
    }
    
    /**
     * Get randomly Snort alerts using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of Snort Alerts.
     */
    public String getItemsetsString_SnortAlerts_2_1_randomlyUsingLimit(int limit, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_2_1_randomlyUsingLimit(limit, stringWhoCalled);
    }
    
    /**
     * Get randomly using statistical parameters the Snort Alerts!
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of Snort Alerts.
     */
    public String getItemsetsString_SnortAlerts_2_2_getStatisticUsingLimit(
            String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_2_2_getStatisticUsingLimit(stringWhoCalled);
    }
    
    // 3
    /**
     * Get all Snort alerts from current time minus an amount of seconds.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_SnortAlerts_3_UpToSecondsAgo(
            int seconds, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_3_UpToSecondsAgo(seconds, stringWhoCalled);
    }
    
    /**
     * Get Snort alerts up to seconds ago, but restrict this search to a amount of register 
     * and get randomly the registers.
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of status flows.
     */
    public synchronized String getItemsetsString_SnortAlerts_3_1_randomlyFromSecondsAgo(
            int seconds, int limit, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_3_1_randomlyFromSecondsAgo(seconds, limit, stringWhoCalled);
    }
    
    /**
     * Get randomly using statistical parameters the last Snort alers up to seconds ago
     * 
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of status flows.
     */
    public synchronized String getItemsetsString_SnortAlerts_3_2_getStatisticFromSecondsAgo(
            int seconds, String stringWhoCalled) {
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        return snortAlertMessageDAO.getItemsetsString_SnortAlerts_3_2_getStatisticFromSecondsAgo(seconds, stringWhoCalled);
    }
    

    /**
     * Gets alerts from Snort (fast log) IDS, it must be in the format:
     * 
     * time,priorityAlert,alertDescription,networkSource,networkDestination,
     * networkProtocol,transportSource,transportDestination
     * 1,3,alerta1,167772162,167772161,6,0,666
     * 2,2,alerta2,167772162,167772161,6,0,777
     * 3,1,alerta3,167772162,167772161,6,0,888
     * 
     * In this example there are three alerts from host 10.0.0.2 to 10.0.0.1,
     * originated from port 0 and destined to ports 666,777,888 with alerts of
     * priority low, medium, and high.
     * 
     * @return a string with a list of attacks to be processed by SPMF
     * 
     */
    public String getAlertsFromSnortIDSFromFile() {
        
        int acceptedAlerts=0;
        int notAcceptedAlerts=0;
        
        FileManager arquivo = new FileManager(directoryName, fileName);
        String sendToBeprocessedByApriori = "";
        String text = arquivo.readFile();
        // log.debug("File content: {} ", text);
        Scanner scanner = new Scanner(text);
        scanner.useDelimiter("\n");
        // Don't read the first line!
        // scanner.nextLine();
        
        /*
         * Get current datetime from system - to be used on to verify if alerts
         * will be in sensorial, short or long memory of attacks.
         */
        Calendar currentDate = Calendar.getInstance();
        
        while (scanner.hasNextLine()) {
            String sLine = scanner.nextLine();
            String[] fields = sLine.split(",");
            AlertMessage alertMsg = new AlertMessage();
            
            alertMsg.setTempo(fields[0].substring(0,18));
            boolean alertIsInTheTime = DateTimeManager.verifyDateTimeRangeInSeconds(alertMsg.getTempo(), currentDate, MemorysAttacks.timeToAlertsStayAtShortMemory);
            if (alertIsInTheTime) {
                
                int snortPriority = Integer.valueOf(fields[1]);
                int ofIDPSPriority = snortPriorityToOfIDPSPriority(snortPriority);
                alertMsg.setPriorityAlert(ofIDPSPriority);
                alertMsg.setAlertDescription(fields[2]);
                // msgAlerta.setNetworkSource(Integer.valueOf(fields[3])); //
                alertMsg.setNetworkSource(fields[3]);
                // msgAlerta.setNetworkDestination(Integer.valueOf(fields[4]));
                alertMsg.setNetworkDestination(fields[4]);
                /*
                 * TODO - for now we just verify if this camp is TCP, UDP and
                 * ICMP, but in the future we should deal with others protocols
                 * too.
                 */
                int proto = -1;
                if (fields[5].equals("TCP"))
                    proto = ProtocolsNumbers.TCP;
                else if (fields[5].equals("UDP"))
                    proto = ProtocolsNumbers.UDP;
                else if (fields[5].equals("ICMP"))
                    proto = ProtocolsNumbers.ICMP;
                /*
                 * Verify if is a know protocol, for now we just handle TCP/UDP/ICMP protocols,
                 * mainly this block IPv6 protocols!
                 */
                if (proto == ProtocolsNumbers.TCP
                        || proto == ProtocolsNumbers.UDP
                        || proto == ProtocolsNumbers.ICMP) {
                    alertMsg.setNetworkProtocol(proto);
                    alertMsg.setTransportSource(Integer.valueOf(fields[6]));
                    alertMsg.setTransportDestination(Integer.valueOf(fields[7]));

                    // log.debug("getting alerts from IDS:");
                    // msgAlerta.printMsgAlert();

                    String alertDescription = alertMsg.getAlertDescription();
                    /**
                     * The next three lines get only the code from alert of
                     * Snort IDS. And ignore the description of alert.
                     */
                    int descriptionIdBegin = alertDescription.indexOf("[");
                    int descriptionIdEnd = alertDescription.lastIndexOf("]");
                    alertDescription = alertDescription.substring(
                            descriptionIdBegin + 1, descriptionIdEnd);

                    String rule = "src" + alertMsg.getNetworkSource() + " dst"
                            + alertMsg.getNetworkDestination() + " pro"
                            + alertMsg.getNetworkProtocol() + " spo"
                            + alertMsg.getTransportSource() + " dpo"
                            + alertMsg.getTransportDestination() + " pri"
                            + alertMsg.getPriorityAlert() + " des"
                            + alertDescription + "\n";

                    sendToBeprocessedByApriori = sendToBeprocessedByApriori
                            + rule;
                    acceptedAlerts++;
                } else {
                    // For now we don't use some protocols, like IPv6 do create rules!
                    log.debug(
                            "ATTENTION - The protocol {} IDS ALERT is not handle for the Of-IDPS for now!", fields[5]);
                    notAcceptedAlerts++;
                }
            } else {
                notAcceptedAlerts++;
                //log.debug("Alert is out of the required time.");
            }
        }
        log.debug("Amount alerts: {} accepted / {} not accepted due to period of time!", acceptedAlerts, notAcceptedAlerts);
        return sendToBeprocessedByApriori;
    }

    /**  
     * Convert a Snort alert security priority to a Of-IDPS alert security priority.
     * @param snortPriority - Snort priority number.
     * @return Of-IDPS priority number.
     **/ 

    /* For knowledge:
     * 
     * - Alert priority description from Snort!
     * 
     * They are currently ordered with 4 default priorities. 
     * A priority of 1 (high) is the most severe and 4 (very low) is the least severe.
     * 
     *  
Classtype                       |Description                                                    |Priority
+-------------------------------+---------------------------------------------------------------+---------
attempted-admin                 | Attempted Administrator Privilege Gain                        | high
attempted-user                  | Attempted User Privilege Gain                                 | high
inappropriate-content           | Inappropriate Content was Detected                            | high
policy-violation                | Potential Corporate Privacy Violation                         | high
shellcode-detect                | Executable code was detected                                  | high
successful-admin                | Successful Administrator Privilege Gain                       | high
successful-user                 | Successful User Privilege Gain                                | high
trojan-activity                 | A Network Trojan was detected                                 | high
unsuccessful-user               | Unsuccessful User Privilege Gain                              | high
web-application-attack          | Web Application Attack                                        | high
attempted-dos                   | Attempted Denial of Service                                   | medium
attempted-recon                 | Attempted Information Leak                                    | medium
bad-unknown                     | Potentially Bad Traffic                                       | medium
default-login-attempt           | Attempt to login by a default username and password           | medium
denial-of-service               | Detection of a Denial of Service Attack                       | medium
misc-attack                     | Misc Attack                                                   | medium
non-standard-protocol           | Detection of a non-standard protocol or event                 | medium
rpc-portmap-decode              | Decode of an RPC Query                                        | medium
successful-dos                  | Denial of Service                                             | medium
successful-recon-largescale     | Large Scale Information Leak                                  | medium
successful-recon-limited        | Information Leak                                              | medium
suspicious-filename-detect      | A suspicious filename was detected                            | medium
suspicious-login                | An attempted login using a suspicious username was detected   | medium
system-call-detect              | A system call was detected                                    | medium
unusual-client-port-connection  | A client was using an unusual port                            | medium
web-application-activity        | Access to a potentially vulnerable web application            | medium
icmp-event                      | Generic ICMP event                                            | low
misc-activity                   | Misc activity                                                 | low
network-scan                    | Detection of a Network Scan                                   | low
not-suspicious                  | Not Suspicious Traffic                                        | low
protocol-command-decode         | Generic Protocol Command Decode                               | low
string-detect                   | A suspicious string was detected                              | low
unknown                         | Unknown Traffic                                               | low
tcp-connection                  | A TCP connection was detected                                 | very low

source: http://manual.snort.org/node31.html

     * 
     * ATTENTION - In the Of-IDPS we consider just 3 alert priorities: 
     * HIGH, MEDIUM, and LOW. 
     * Then we will map Snort priority like:
     * Snort priority   | Of-IDPS priority
     * -----------------+----------------
     * HIGH (1)         | HIGH (1)
     * MEDIUM (2)       | HIGH (1)
     * LOW (3)          | MEDIUM (2)
     * VERY LOW (4)     | LOW (3)   
     * 
     * In the Of-IDPS we consider that Snort security priority levels HIGH and MEDIUM
     * affects the network performance, then we block this packets!
     * 
     */
    private int snortPriorityToOfIDPSPriority(int snortPriority) {
        switch(snortPriority) {
            case 1: return AlertMessage.ALERT_PRIORITY_HIGH; // snort alert high -> Of-IDPS high
            case 2: return AlertMessage.ALERT_PRIORITY_HIGH; // snort alert medium -> Of-IDPS high
            case 3: return AlertMessage.ALERT_PRIORITY_MEDIUM; // snort alert low -> Of-IDPS medium
            case 4: return AlertMessage.ALERT_PRIORITY_LOW; // snort alert very low -> Of-IDPS low
        }
        return Integer.MAX_VALUE; // Alert priority unknown!
    }

    /**
     * Get current datetime.
     *  
     * @return datetime.
     */
    private long getCurretDatetimeInMilliseconds() {
        return new Date().getTime();
    }

    /**
     * Wait during some seconds.
     * 
     * @param timeInSeconds - time in seconds to wait.
     */
    private void waitTime(int timeInSeconds) {
        try {
            sleep(timeInSeconds * 1000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Print packet in and alert from IDS. 
     * We can use this to compare (see) alert from IDS and packet in fields.
     * 
     * @param packetIn - Switch packet network in.
     * @param alertMessage - Alert from IDS.
     * 
     * 
     */
    private void printAlertMessageAndPacketIn(OFMatch packetIn, AlertMessage alertMessage) {
        log.debug("Alert -" + "IPsrc={}:" + "portSrc={} ->\t" + "IPdst={}:"
                + "portDst={} " + "(proto={})" + "\tpriority={}",
                alertMessage.getNetworkSource(), alertMessage.getTransportSource(),
                alertMessage.getNetworkDestination(), alertMessage.getTransportDestination(),
                alertMessage.getNetworkProtocol(), alertMessage.getPriorityAlert());
        log.debug("Packet in -" + "IPsrc={}:" + "portSrc={} ->\t" + "IPdst={}:"
                + "portDst={} " + "(proto={})",
                packetIn.getNetworkSource(),
                packetIn.getTransportSource(),
                packetIn.getNetworkDestination(),
                packetIn.getTransportDestination(),
                packetIn.getNetworkProtocol());
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg) throws IOException {
        // TODO Auto-generated method stub
        return null;
    }

}
