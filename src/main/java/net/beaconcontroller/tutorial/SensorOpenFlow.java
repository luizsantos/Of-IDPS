/**
 * Collect statistics from the network using OpenFlow messages. 
 * This statics are obtained from OpenFlow switches.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 */

/*
 * TODO 1 - Collect statistics from the OpenFlow controller too, 
 * we can get informations like, the number of added flows, etc.
 */
package net.beaconcontroller.tutorial;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


import net.beaconcontroller.DAO.SnortAlertMessageDAO;
import net.beaconcontroller.DAO.StatusFlow;
import net.beaconcontroller.DAO.StatusFlowDAO;
import net.beaconcontroller.DAO.StatusPort;
import net.beaconcontroller.DAO.StatusPortDAO;
import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.FlowsSuspiciousOfDoS;
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.packet.IPv4;
import net.beaconcontroller.tools.FileManager;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFPortStatisticsReply;
import org.openflow.protocol.statistics.OFPortStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SensorOpenFlow extends Thread implements IOFMessageListener {
    // Interval of time that the OpenFlow statistics message will be sent to the switches.
    protected static final int timeBetweenRequests = CONFIG.TIME_BETWEEN_RUN_SENSOR_OPENFLOW;
    public static final int TIME_TO_VERIFY_BAD_FLOW_ON_ALERT_DB = 120;

    public static final String directoryName = "/mnt/armazem/openflow/tmp/dadosSwitchesOF/";
    public static final String fileName = "OpenFlowStatistics.dat";
    public static final String databaseName = "teste.db";

    // Handle current flows.
    /*
     * the Map presented java.util.ConcurrentModificationException, them we change Map to ConcurrentHashMap
     * error:
     * Exception in thread "Thread-9" java.util.ConcurrentModificationException
     *        at java.util.HashMap$HashIterator.nextEntry(HashMap.java:793)
     *        at java.util.HashMap$KeyIterator.next(HashMap.java:828)
     *        at net.beaconcontroller.tutorial.AnalysisFlow.run(AnalysisFlow.java:105)
     */
    //public static Map<String, StatusFlow> currentFlows = new HashMap<String, StatusFlow>();
    public static ConcurrentMap<String, StatusFlow> currentFlows = new ConcurrentHashMap<String, StatusFlow>();

    protected IBeaconProvider beaconProvider;

    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    // TODO - verify if array is the better or if we should use a ArrayList.
    //List<MensagemAlerta> conexoesDDoS = new java.util.Vector<MensagemAlerta>();
    HashMap<Integer, FlowsSuspiciousOfDoS> cDDoS =  new HashMap<Integer, FlowsSuspiciousOfDoS>();
    
    public HashMap<Integer, FlowsSuspiciousOfDoS> getcDDoS() {
        return cDDoS;
    }


    public void setcDDoS(HashMap<Integer, FlowsSuspiciousOfDoS> cDDoS) {
        this.cDDoS = cDDoS;
    }


    /**
     * Prepare the object to start, before collect the statistics we need of the beconProvide variable.
     * 
     * @param bP - beaconProvider
     * 
     */
    public void startUp(IBeaconProvider bP) {
        log.debug("Starting Sensor to collect OpenFlow statistics");
        this.beaconProvider = bP;
        beaconProvider.addOFMessageListener(OFType.STATS_REPLY, this);
        
        //beaconProvider.addOFMessageListener(OFType.PACKET_IN, this);
        // this.start();
         }
        
    
    /**
     * Turn off the object this is necessary to remove the listeners of the networks.
     * 
     */
    public void shutDown() {
        log.trace("Stopping sensor OpenFlow");
        beaconProvider.removeOFMessageListener(OFType.STATS_REPLY, this);
        log.trace("Sensor OpenFlow was STOPPED!!!");
    }
    
    /**
     * 
     * Method responsible to run the Thread and send OpenFlow statistics messages request.
     * 
     */
    public void run() {
        log.debug("Sending OpenFlow statistics request message...");
        int numberOfSwitchesInTheNetwork=0;
        while (true) {
            /*
             * TODO - ANALYZE if this is the best solution:
             * The code to remove dead rules from list that represents current
             * network flows, on switches, was before in receive method. But we
             * had a trouble, when tests finished the switches are turned off,
             * consequently the Of-IDPS don't receive statistics messages and
             * thus the code that remove dead rules isn't more executed, so dead
             * rules aren't removed from memory, when all switches are turned
             * off. To solve this problem we put this code here!
             */
            removeDeadFlowsFromListThatRepresentsActiveFlowsOnSwitches();
            
            log.debug("Number of flows actives in switches: {} - From SensorOpenFlow.",  currentFlows.size());
            
            waitTime(timeBetweenRequests);
            if (beaconProvider.getListeningIPAddress().isAnyLocalAddress()) {
                // print switches presents on the network.
                // log.debug("switches={}", beaconProvider.getSwitches());
                /*
                 * TODO - ERROR - sometimes appear switches that aren't really of the network (ghosts)!
                 * 
                 * In some tests the 2 lines below eliminates ghosts switches
                 */
                Collection<IOFSwitch> col = new HashSet<IOFSwitch>();
                col.clear();
                col = beaconProvider.getSwitches().values();
                for (IOFSwitch s : col) {
                    if (numberOfSwitchesInTheNetwork != col.size()) { 
                        /*
                         * Print all switches on the network, but only if the amount is changed.
                         */
                        log.debug("Connected switches: switchId={} - sending statistics messages!",s.getId());
                    }
                    IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
                    
                    /*
                     * Statistics messages that will be obtained, each type of
                     * statistic message must be send after a period of time to
                     * avoid overloads.
                     */
                    getFlowStatistics(sw);
                    //waitTime(timeBetweenRequests);
                    
                    // getPortStatistics(sw);
                    // waitTime(timeBetweenRequests);
                    
                    // getQueueStatistics(sw);
                    // waitTime(timeBetweenRequests);
                    
                    // TODO - make a method to record table statistics in a database!
                    // getTableStatistics(sw);
                    // waitTime(timeBetweenRequests);
                    
                }
                numberOfSwitchesInTheNetwork = col.size();
            } else {
                log.debug("ATTENTION - Do not exist switches in the network... impossible obtain OpenFlow statistics.");
            }
            
            //TODO - verify where put this!
            //writeFlowsIntoJSONFile();
            
            log.debug("Waiting {} seconds to rerun SensorOpenFlow.",timeBetweenRequests);
        }

    }


    /**
     * Write current switches flows into a json file to be read for the web interface!
     * TODO - Verify where put this method and if this is works fine...
     */
    private void writeFlowsIntoJSONFile() {
        // write current switches flows in json file to be view in the interface!
        JSONArray listCurrentFlows = new JSONArray();
        for(String key :  currentFlows.keySet()) {
            StatusFlow stF = currentFlows.get(key);
            //stF.printStatusFlow("MEIO");
            listCurrentFlows.add(stF.getJSONStatusFlow());
         }
        FileManager file = new FileManager("/home/luiz/Downloads/bootstrap-3.3.1/docs/examples/OfIDPS/", "flows.json");
        file.emptyFileContent();
        file.writeFile("{\"flows\":"+listCurrentFlows.toJSONString()+"}");
    }


    /**
     * Remove dead flows from list that represent active flows on network switches. 
     * Dead flows are flows that were removed from flow tables switches. 
     * 
     * Also, verify if this flow is good or bad to record on database!
     * 
     */
    private void removeDeadFlowsFromListThatRepresentsActiveFlowsOnSwitches() {
        
        
        
        for (Iterator<Map.Entry<String, StatusFlow>> flow = currentFlows.entrySet().iterator(); flow.hasNext();) {
            Map.Entry<String, StatusFlow> currentFlow = flow.next();
            currentFlow.getValue().decreaseLife();
            if (!currentFlow.getValue().isAlive()) {
                StatusFlow flowToRecord = currentFlow.getValue();
                flow.remove();
                recordFlowMessageInDB(flowToRecord);
                // log.debug("Life of flow EXPIRED removing this flow to database:");
                // currentFlow.getValue().printStatusFlow("REMOVED to database");
            }
        }

        // print currentFlows
//        for (String key : currentFlows.keySet()) {
//            StatusFlow stF = currentFlows.get(key);
//            stF.printStatusFlow("FIM");
//        }
    }

    /**
     * This method will be  automatically executed always than one packet arrive on the system.
     */
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg) throws IOException {
        if (msg instanceof OFStatisticsReply) {
            log.debug("Receiving an OpenFlow statistics message");
            OFStatisticsReply reply = (OFStatisticsReply) msg;

            List<OFStatistics> stats = new ArrayList<OFStatistics>();
            stats = reply.getStatistics();

            // log.debug("------Class stat={}",
            // stats.get(MIN_PRIORITY).getClass());
            if (stats.size() > 0) {
                //Check if the message that arrived is an FLOW statistic message.
                if (stats.get(0) instanceof OFFlowStatisticsReply) {
//                    log.debug("Receiving FLOWS statistics from OpenFlows switches.");
//                    printFlowStats(sw, stats);                    
                    processStatusFlowsMessage(sw, stats);
                }
                //Check if the message that arrived is an PORT statistic message.
                if (stats.get(0) instanceof OFPortStatisticsReply) {
                    log.debug(" DISABLED - Receiving PORTS statistics from OpenFlows switches");
                    //printPortStats(sw, stats);
                    /*
                     * TODO - improve the method that record the OpenFlow
                     * statics on the database... perhaps is better use one
                     * Thread for this, because the system have some timeouts
                     * during this process.
                     */
                    //gravarStatusPortsBD(sw, stats);
                }
                /*
                 * TODO - Verify if the OpenFlow offer more statistics messages and 
                 * if this is interesting for us! Then, implement the method 
                 * to collect this new statistics.
                 */
            } 
            
        }        
        return null;
    }
    

    /*
     * @Override public String getName() { 
     * return "AnalysisFlow"; }
     */

    /**
     * @param sw
     *            switch
     * @param stats
     *            status message
     * 
     */
    private void printPortStats(IOFSwitch sw, List<OFStatistics> stats) {
        for (int i = 0; i < stats.size(); i++) {
            OFPortStatisticsReply portReply = (OFPortStatisticsReply) stats
                    .get(i);
            // log.debug(
            // "Description Statistics Reply from {} / port {}: env {}/recv {}",
            // sw.getId(), portReply.getPortNumber(),
            // portReply.getTransmitBytes(), portReply.getReceiveBytes());

            String text = getDataAtualMilisegundos() + "\t" + sw.getId()
                    + "\t" + portReply.getPortNumber() + "\t"
                    + portReply.getTransmitBytes() + "\t"
                    + portReply.getReceiveBytes();
            
            //gravarArquivo(diretorioArquivos + nomeArquivo, texto);
            FileManager arquivo = new FileManager(directoryName, fileName);
            arquivo.writeFile(text);

            // printPortsStatisticsDAO();
        }
    }

    /**
     * 
     * Record the PORTS statistics data in the database.
     * 
     * TODO - during the update of PORTS like FLOW this method will be named 
     * like processStatusFlowsMessage(), not record. 
     * 
     * @param sw
     *            switch
     * @param stats
     *            list that contain ports statistics messages.
     * 
     */
    private void recordStatusPortsBD(IOFSwitch sw, List<OFStatistics> stats) {
        if (stats.get(0) instanceof OFPortStatisticsReply) {
            for (int i = 0; i < stats.size(); i++) {
                OFPortStatisticsReply portReply = (OFPortStatisticsReply) stats
                        .get(i);
                try {

                    StatusPort statusPorta = new StatusPort();
                    statusPorta.setAllAttributesOfStatusPort(sw.getId(),
                            getDataAtualMilisegundos(), portReply);
                    StatusPortDAO statusPortaDAO = new StatusPortDAO(
                            directoryName + databaseName);
                    statusPortaDAO.insert(statusPorta);
                    statusPortaDAO.close();
                } catch (ClassNotFoundException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (SQLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
    }

    
    /**
     * 
     * Record the FLOWS statistics data in the database.
     * 
     * @param sw
     *            switch
     * @param stats
     *            list that contain flows statistics messages.
     * 
     */
    private void processStatusFlowsMessage(IOFSwitch sw, List<OFStatistics> stats) {
        
        // print currentFlows
//        log.debug("Begin:");
//        for(String key :  currentFlows.keySet()) {
//            StatusFlow stF = currentFlows.get(key);
//            stF.printStatusFlow("INICIO");
//        }
        
        // Analyze all arrived flows!
        for (int i = 0; i < stats.size(); i++) {
            OFFlowStatisticsReply flowReply = (OFFlowStatisticsReply) stats.get(i);

            // Status flow that arrived and will be analyzed to be added or updated.
            StatusFlow currentStatusFlow = new StatusFlow();
            currentStatusFlow.setAllAttributesOfStatusFlow(sw.getId(), getCurrentDate(), flowReply);
            // currentStatusFlow.printStatusFlow();

            StatusFlow existingMessage = null;
            existingMessage = currentFlows.get(currentStatusFlow.getKey());
            if (existingMessage == null) {
                // new message.
                //currentStatusFlow.printStatusFlow("NEW flow arriving:");
                currentStatusFlow.keepAlive();
                currentFlows.put(currentStatusFlow.getKey(), currentStatusFlow);
            } else {
                /*
                 * Verify if new message belongs to a existing flow and if is
                 * true then update this flow entry for the new information
                 * under the new message.
                 * 
                 * However, if this flow exists, but information like duration,
                 * amount of transmitted bytes and packet count in the new
                 * message are less than the existing message, it means that
                 * it's a new flow from this socket networks. In this case we
                 * will remove the oldest flow information of Map and record it
                 * in the database and newest information will be added in the
                 * Map.
                 */
                if (currentStatusFlow.getDurationNanoseconds() >= existingMessage.getDurationNanoseconds()
                        && currentStatusFlow.getDurationSeconds() >= existingMessage.getDurationSeconds()
                        && currentStatusFlow.getByteCount() >= existingMessage.getByteCount()
                        && currentStatusFlow.getPacketCount() >= existingMessage.getPacketCount()) {
//                     log.debug("Updating a existing flow:");
//                     existingMessage.printStatusFlow("OLD");
//                     currentStatusFlow.printStatusFlow("NEW");

                    // This new message is just a message for update a existing
                    // flow!
                    existingMessage.keepAlive();
                    existingMessage.setAllAttributesOfStatusFlow(currentStatusFlow.getSwID(),
                            currentStatusFlow.getTime(), currentStatusFlow);
                } else {
                    /*
                     * This is a new flow from the same socket network! Then
                     * remove the oldest and record in the database, and put the
                     * new message on the Map.
                     */
//                     log.debug("New flow of an existing Map netwoking socket - record old data in database and new data in the Map:");
//                     existingMessage.printStatusFlow("OLD");
//                     currentStatusFlow.printStatusFlow("NEW");
                    // record the old in the database
                    /*
                     * Creating a new object to save it! It's necessary because
                     * when the thread will record the existent object, this has
                     * already been replaced by the new object.
                     */
                    StatusFlow recordOld = new StatusFlow();
                    //recordOld.decreaseLife();
                    recordOld.setAllAttributesOfStatusFlow(existingMessage.getSwID(), 
                            existingMessage.getTime(), existingMessage);
                    recordFlowMessageInDB(recordOld);
                    // replace informations from the old flow to the new!
                    currentStatusFlow.keepAlive();
                    existingMessage.setAllAttributesOfStatusFlow(currentStatusFlow.getSwID(), 
                            currentStatusFlow.getTime(), currentStatusFlow);
                    existingMessage.keepAlive();
                }
            }
        } // for incoming flow messages

        // print currentFlows
//        log.debug("Middle:");
//        for(String key :  currentFlows.keySet()) {
//            StatusFlow stF = currentFlows.get(key);
//            stF.printStatusFlow("MEIO");
//        }
        
        /*
         * The control of removing dead flows is made out of this method, in the receive method. This
         * is necessary because if not arrive any statistics flows messages, the
         * dead flows aren't removed!
         */
    }
    

    /** 
     * Record an flow message in the database.
     * @param existingMessage
     */
    private void recordFlowMessageInDB(StatusFlow existingMessage) {
        
        SnortAlertMessageDAO snortAlertMessageDAO = new SnortAlertMessageDAO();
        // Verify if the flow to be recorded has security alerts.
        int numberOfAlerts = snortAlertMessageDAO.verifyIfFlowHadSnortAlerts(
                existingMessage.getNetworkSource(), 
                existingMessage.getNetworkDestination(),
                existingMessage.getNetworkProtocol(),
                existingMessage.getTransportSource(),
                existingMessage.getTransportDestination(),
                TIME_TO_VERIFY_BAD_FLOW_ON_ALERT_DB
                );
        
        if(numberOfAlerts>0) {
            //If has any alert save as bad flow!
            existingMessage.setFlowType(StatusFlow.FLOW_ABNORMAL);
        } else {
            //If has not alerts save as normal flow!
            existingMessage.setFlowType(StatusFlow.FLOW_NORMAL);
        }
        
        try {
            StatusFlowDAO statusFlowDao = new StatusFlowDAO(existingMessage);
            statusFlowDao.start();
        } catch (ClassNotFoundException e) {
            log.debug("ATTENTION - Sorry wasn't possible to record data in database - Class error!");
            e.printStackTrace();
        } catch (SQLException e) {
            log.debug("ATTENTION - Sorry wasn't possible to record data in database - SQL error!");
            e.printStackTrace();
        }
    }

    /**
     * Get ports statistics data from database and print.
     */
    private void printPortsStatisticsDAO() {
        Vector<StatusPort> vetorStatusPorta = new Vector<StatusPort>();
        StatusPortDAO sPDao;
        try {
            sPDao = new StatusPortDAO(directoryName + databaseName);
            vetorStatusPorta = sPDao.getAll();
            for (StatusPort sP : vetorStatusPorta) {
                log.debug(
                        "Sw={}, PortNumber={}, BytesRx={}, PacketsRx={}, BytesTx={}, PacketsTx={}",
                        sP.getSwID(), sP.getPortNumber(), sP.getReceiveBytes(),
                        sP.getreceivePackets(), sP.getTransmitBytes(),
                        sP.getTransmitPackets());
            }
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Get current time.
     * 
     * TODO - after alter PORTS objects and update time from type date remove this method!
     * 
     * @return current time.
     */
    private long getDataAtualMilisegundos() {
        return new Date().getTime();
    }
    
    /**
     * Get current time.
     * 
     * @return current time.
     */
    private Date getCurrentDate() {
        return new Date();
    }


    /**
     * Get flows statistics data from database and print.
     * 
     * @param sw - Switch
     * @param stats - Statistics
     * 
     */
    private void printFlowStats(IOFSwitch sw, List<OFStatistics> stats) {
        for (int i = 0; i < stats.size(); i++) {
            OFFlowStatisticsReply flowReply = (OFFlowStatisticsReply) stats
                    .get(i);

            OFMatch match = new OFMatch();
            match = flowReply.getMatch();

            log.debug(
                    "FLOW - in port: {}, HwSrc: {}, HwDst: {}, IPSrc:{}:{}, IPDst:{}:{}, Proto:{}, bytes:{}, packets:{}",
                    match.getInputPort(),
                    HexString.toHexString(match.getDataLayerSource()),
                    HexString.toHexString(match.getDataLayerDestination()),
                    IPv4.fromIPv4Address(match.getNetworkSource()),
                    match.getTransportSource(),
                    IPv4.fromIPv4Address(match.getNetworkDestination()),
                    match.getTransportDestination(),
                    match.getNetworkProtocol(), flowReply.getByteCount(),
                    flowReply.getPacketCount());

        }
    }
       

    /**
     * Get ports statistics from OpenFlow switches.
     * 
     * @param sw - OpenFlow switch.
     */
    private void getPortStatistics(IOFSwitch sw) {
        log.debug("Getting OpenFlow PORTS statistics...");
        OFStatisticsRequest req = new OFStatisticsRequest();
        OFPortStatisticsRequest psr = new OFPortStatisticsRequest();
        psr.setPortNumber(OFPort.OFPP_NONE.getValue());
        req.setStatisticType(OFStatisticsType.PORT);
        req.setStatistics(psr);
        req.setLengthU(req.getLengthU() + psr.getLength());

        try {
            sw.getOutputStream().write(req);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Get TABLE statistics from OpenFlow switches.
     * 
     * @param sw - switch. 
     */
    private void getTableStatistics(IOFSwitch sw) {
     // TODO - in construction...
        log.debug("Getting OpenFlow TABLE statistics...");
        OFStatisticsRequest req = new OFStatisticsRequest();
        req.setStatisticType(OFStatisticsType.TABLE);
        req.setLengthU(req.getLengthU());
        try {
            sw.getOutputStream().write(req);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Get queue statistics from OpenFlow switches.
     * 
     * @param sw - switch.
     */
    private void getQueueStatistics(IOFSwitch sw) { 
        // TODO - in construction...
        log.debug("Getting OpenFlow FLOW statistics...");
        OFStatisticsRequest req = new OFStatisticsRequest();
        req.setStatisticType(OFStatisticsType.QUEUE);
        req.setLengthU(req.getLengthU());
        try {
            sw.getOutputStream().write(req);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get flows statistics from OpenFlow switches.
     * 
     * @param sw - Switch.
     */
    private void getFlowStatistics(IOFSwitch sw) {
        log.debug("Getting OpenFlow FLOW statistics...");
        OFStatisticsRequest req = new OFStatisticsRequest();
        OFFlowStatisticsRequest ofFlowRequest = new OFFlowStatisticsRequest();

        OFMatch match = new OFMatch();
        match.setWildcards(0xffffffff);

        ofFlowRequest.setMatch(match);
        ofFlowRequest.setOutPort(OFPort.OFPP_NONE.getValue());
        ofFlowRequest.setTableId((byte) 0xff);

        req.setStatisticType(OFStatisticsType.FLOW);
        req.setStatistics(ofFlowRequest);
        req.setLengthU(req.getLengthU() + ofFlowRequest.getLength());

        try {
            sw.getOutputStream().write(req);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    /**
     * Time to wait in seconds.
     * 
     * @param timeInSeconds - number in seconds.
     *            
     */
    private void waitTime(int timeInSeconds) {
        try {
            sleep(timeInSeconds * 1000);
        } catch (InterruptedException e) {
            log.debug("ERROR - waitTime() method.");
            e.printStackTrace();
        }
    }
    
    /**
     * get a list with all switches on network.
     * 
     * @return A collection of switches presents on network.
     */
    private Collection<IOFSwitch> getAllSwitchesOnNetwork() {
        //log.debug("Get switches on the network");
        if (beaconProvider.getListeningIPAddress().isAnyLocalAddress()) {
            /*
             * TODO ERROR - sometimes appear switches that aren't really of the network (ghosts)!
             * 
             * In some tests the 2 lines below eliminates ghosts switches
             */
            Collection<IOFSwitch> col = new HashSet<IOFSwitch>();
            col.clear();
            col = beaconProvider.getSwitches().values();
            return col;
        } else {
            log.debug("SORRY!!! switches weren't found in this network.");
        }
        return null;
    }
    
} // class
