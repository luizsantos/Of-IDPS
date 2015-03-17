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
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
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
     * 
     * Verify if the alert is between a period of time. This period is the
     * current time of the system and this same time minus one amount of time in
     * seconds (periodInSeconds param).
     * 
     * @param analysedDate - Datetime from the alert
     * @param currentDate - current date from the system
     * @param periodInSeconds - the analysis will be between current date less this camp in
     *            seconds and current time.
     * @return true if it's on the required period of time or false if not!
     */
    public static boolean verifyDateTimeRangeInSeconds(Date analysedDate,
            Calendar currentDate, int periodInSeconds) {

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss.SSS");
        Calendar currentDateLessPeriodInSeconds = Calendar.getInstance();
        currentDateLessPeriodInSeconds.setTime(currentDate.getTime());
        currentDateLessPeriodInSeconds.add(Calendar.SECOND,(periodInSeconds * -1));
        
        // Test if the alert is on the time
        if (analysedDate.after(currentDateLessPeriodInSeconds.getTime()) 
                || analysedDate.equals(currentDateLessPeriodInSeconds.getTime())) {
            
//            log.debug("Alert datetime accepted: {} <{}> {}.", sdf.format(currentDateLessPeriodInSeconds.getTime()),
//                    sdf.format(analysedDate), sdf.format(currentDate.getTime()));            
            
            return true; // alert on the time
        } else {
            
//            log.debug("Alert datetime NOT accepted: {} {} <{}>.", sdf.format(currentDateLessPeriodInSeconds.getTime()),
//                    sdf.format(currentDate.getTime()), sdf.format(analysedDate));
            
            return false; // Alert out of time
        }        
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
    public String getAlertsFromSnortIDS() {
        
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
            boolean alertIsInTheTime = verifyDateTimeRangeInSeconds(alertMsg.getTempo(), currentDate, MemorysAttacks.timeToAlertsStayAtShortMemory);
            if (alertIsInTheTime) {

                alertMsg.setPriorityAlert(Integer.valueOf(fields[1]));
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
                alertMsg.setNetworkProtocol(proto);
                alertMsg.setTransportSource(Integer.valueOf(fields[6]));
                alertMsg.setTransportDestination(Integer.valueOf(fields[7]));

//                log.debug("getting alerts from IDS:");
//                msgAlerta.printMsgAlert();

                String alertDescription = alertMsg.getAlertDescription();
                /**
                 * The next three lines get only the code from alert of Snort
                 * IDS. And ignore the description of alert.
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

                sendToBeprocessedByApriori = sendToBeprocessedByApriori + rule;
                acceptedAlerts++;
            } else {
                notAcceptedAlerts++;
                //log.debug("Alert is out of the required time.");
            }
        }
        log.debug("Amount alerts: {} accepted / {} not accepted due to period of time!", acceptedAlerts, notAcceptedAlerts);
        return sendToBeprocessedByApriori;
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
