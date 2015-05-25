/**
 * This class is responsible to analyze flows OpenFlows installed on 
 * switches and verify if this flows represent any threats to the network. 
 * 
 * With this class is possible remove and change flows.
 * 
 *  @author Luiz Arthur Feitosa dos Santos
 *  @email luiz.arthur.feitosa.santos@gmail.com
 */
package net.beaconcontroller.tutorial;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import net.beaconcontroller.DAO.AlertOpenFlowDAO;
import net.beaconcontroller.DAO.StatusFlow;
import net.beaconcontroller.DAO.StatusFlowDAO;
import net.beaconcontroller.IPS.AlertMessageSharePriority;
import net.beaconcontroller.IPS.FlowsSuspiciousOfDoS;
import net.beaconcontroller.tools.ProtocolsNumbers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AnalysisFlow extends Thread {
    // Time to execute the analyze.
    static final int timeBetweenAnalysis = CONFIG.TIME_BETWEEN_RUN_ANALYSIS_FLOW;
    private int timePeriodToRecoverFlowFromDB = CONFIG.TIME_PERIOD_TO_RECOVER_FLOW_INFORMATION_FROM_DB;
    
    // Used to store the detected suspicious flows
    //private static List<AlertMessageSharePriority> listOfMaliciousFlows = new ArrayList<AlertMessageSharePriority>();
    private static CopyOnWriteArrayList<AlertMessageSharePriority> listOfMaliciousFlows = new CopyOnWriteArrayList<AlertMessageSharePriority>();
    

    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
        
    /**
     * 
     * Start the object.
     * 
     */
    public void startUp() {
        log.debug("Start analysisFlow!");
    }
        
    
    /**
     * Turn off the object.
     * 
     */
    public void shutDown() {
       log.debug("Stopping AnalysisFlow");
    }
    
    /**
     * Starts analysis flow thread, this can analyze OpenFlow informations, like statistics:
     * flow, ports, etc.
     * 
     */
    public void run() {
        log.debug("Start Thread that is responsible to ANALYZE OpenFlow statistics!");
        while (true) {
            
            // print flows!
//            for(String key : SensorOpenFlow.currentFlows.keySet()) {
//                StatusFlow statusFlow = SensorOpenFlow.currentFlows.get(key);
//                statusFlow.printStatusFlow("In Analysis");
//            }
            
            // looking for DoS attacks analyzing the source address flows and the low amount of transmitted packets by this flows.
            /*
             *  TODO - Is better execute it inside of sensor OpenFlow? 
             *  Thus, every time that we analyze flow messages we will execute this method!
             *  Verify if already did this!
             */
            analyzeDoSAttack();
            
            
            log.debug("Waiting {} seconds to rerun OpenFlow analysis.",timeBetweenAnalysis);
            waitTime(timeBetweenAnalysis);
        }
    }


    
    /**
     * Looking for DoS and DDoS attacks! This is made analyzing the low number 
     * of packets transmitted in a OpenFlow flow.
     * 
     * TODO - For now it's just to prove that is possible use the OpenFlow to
     * mitigate suspects flow! In the future, new methods should be
     * implemented....
     */
    public void analyzeDoSAttack() {
        // If the amount of TCP packets in a flow is smaller or equal of this number it is suspect.
        int dosTCPPacketCount = 2;
        // If the amount of TCP bytes in a flow is smaller or equal of this number it is suspect. 
        int dosTCPByteCount = 120;
        // To store all flows that are suspicious of DDoS
        FlowsSuspiciousOfDoS flowSuspiciousOfDDoS = new FlowsSuspiciousOfDoS();
        
        
        
        /*
         * The OpenFlow flows are split here, the current flows that are
         * currently installed on network switches have your flows logged in the
         * currentFlows list, and flows that had already his flows removed from
         * network switches has this flows registered on the database. In other
         * words, current flows are in memory and old flows are in database.
         */

        // Get suspect old flows from database!
        List<StatusFlow> databaseFlowsToByAnalysed = new ArrayList<StatusFlow>();
        try {
            StatusFlowDAO statusFlowDAO = new StatusFlowDAO();
            // Get the already suspicious flows.
            // TODO - What time period is better to use?
            databaseFlowsToByAnalysed =  statusFlowDAO.getList_suspiciousDoSTCPFlows_upToSecondsAgo(this.timePeriodToRecoverFlowFromDB, dosTCPPacketCount, dosTCPByteCount);
            
            log.debug("Number of alert valid alerts from database: {} - From AnalysisFlow.", databaseFlowsToByAnalysed.size());
        } catch (ClassNotFoundException e) {
            log.debug("ATTENTION - Sorry wasn't possible to read data in database - SQL error!");
            e.printStackTrace();
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from flows table!");
            e.printStackTrace();
        }
                
        
        
        // Get current switches flows and select just the suspect flows.
        /*
         * Remember that a flow is just recorded on database when he get out 
         * of totally of the switches! 
         * 
         * Thus, in the union of current and old flows, these flows won't be duplicated.
         * 
         * (see processStatusFlowsMessage method on SensorOpenFlow Class)
         */
        for (String key : SensorOpenFlow.currentFlows.keySet()) {
            StatusFlow currentFlow = SensorOpenFlow.currentFlows.get(key);
            // Set that is a flow from switches memory (not database)
            currentFlow.setInSwitchesMemory(true);

            /*
             * Verify if current flow have few packets (<=3)! if this is true, then we
             * consider suspicious.
             * 
             * This list have all current flows registered in memory (currentFlows list)
             * and the flows from now until some seconds ago (timePeriodToRecoverFlowFromDB). 
             * 
             * And protocol is equal 6 (TCP)
             * TODO - verify others protocols!
             * 
             * 120 just TCP header!
             * 
             */
            if(currentFlow.getPacketCount() <= dosTCPPacketCount && 
                    currentFlow.getNetworkProtocol()==ProtocolsNumbers.TCP && 
                    currentFlow.getByteCount()<= dosTCPByteCount) {
                // Save this current and suspect flow.
                flowSuspiciousOfDDoS.putAlertsFlowOnListOfRelatedWithThisConnection(currentFlow);
            }
        }
           
        // Join both: current suspect flows and old suspect flows.
        flowSuspiciousOfDDoS.putListOfAlertsFlowOnListOfRelatedWithThisConnection(databaseFlowsToByAnalysed);

        /*
         * 
         * Here, we can put others identification methods to DoS attacks!
         *
         * IDEA - to UDP, and ICMP control the time! like 5 seconds with just only 5 packets!
         * If we implement this we must put the above verification <=5 to only the TCP flows...
         * 
         */
        
        // Remove all old messages present in the list of malicious flows to do a new list!
        listOfMaliciousFlows.clear();
        
        // Verify if all suspect network flows represents some threat to the system.
        if(flowSuspiciousOfDDoS.isDanger()) {
            /*
             * If is danger add all flows in the list of malicious flows. 
             * After these flows can be processed by the memory attack, for example!
             */
            //listOfMaliciousFlows.addAll(flowSuspiciousOfDDoS.getFlowsRelatedWithThisConnection());
            // estou duplicando a tarefa, pois estou guardando em memória e em banco de dados! Como está cheio de threads acho que é melhor usar o DB!
            flowSuspiciousOfDDoS.printStatistics();
            
            // Record alerts flow in the database!
            AlertOpenFlowDAO alertOpenFlowDAO = new AlertOpenFlowDAO();
            for(AlertMessageSharePriority alertMessageSharePriority : flowSuspiciousOfDDoS.getFlowsRelatedWithThisConnection()) {
                alertOpenFlowDAO.insert(alertMessageSharePriority);
            }
            
            
            // Update flows on database as bad flows!
            try {
                StatusFlowDAO statusFlowDAO = new StatusFlowDAO();
                
                // Set all malicious flows found here as bad flow, on database.
                for(StatusFlow maliciousFlow : databaseFlowsToByAnalysed) {
                    if(maliciousFlow.getFlowType()!=StatusFlow.FLOW_ABNORMAL) {
                        statusFlowDAO.updateBadFlowByFlowId(maliciousFlow.getFlowId());
                    }
                }
                
            } catch (ClassNotFoundException e) {
                log.debug("ATTENTION - Sorry wasn't possible to read data in database - SQL error!");
                e.printStackTrace();
            } catch (SQLException e) {
                log.debug("ATTENTION - Error during SQL select from flows table!");
                e.printStackTrace();
            }
            
            
        }

    }
    
    /**
     * Looking for DoS and DDoS attacks! This is made analyzing the low number 
     * of packets transmitted in a OpenFlow flow.
     * 
     * TODO - For now it's just to prove that is possible use the OpenFlow to
     * mitigate suspects flow! In the future, new methods should be
     * implemented....
     */
    public void analyzeDoSAttack_2015_04_12() {
        // Remove all old messages present in the list of malicious flows to do a new list!
        listOfMaliciousFlows.clear();
        
        /*
         * The OpenFlow flows are split here, the current flows that are
         * currently installed on network switches have your flows logged in the
         * currentFlows list, and flows that had already his flows removed from
         * network switches has this flows registered on the database. In other
         * words, current flows are in memory and old flows are in database.
         */

        // Get old flows from database!
        List<StatusFlow> allFlowsToByAnalysed = new ArrayList<StatusFlow>();
        try {
            StatusFlowDAO statusFlowDAO = new StatusFlowDAO();
            // TODO - What time period is better to use?
            allFlowsToByAnalysed =  statusFlowDAO.getList_GoodBadFlows_upToSecondsAgo(this.timePeriodToRecoverFlowFromDB);
            log.debug("Number of alert valid alerts from database: {}", allFlowsToByAnalysed.size());
        } catch (ClassNotFoundException e) {
            log.debug("ATTENTION - Sorry wasn't possible to read data in database - SQL error!");
            e.printStackTrace();
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from flows table!");
            e.printStackTrace();
        }
        
        // print selected flow from database
//        for(StatusFlow stF: allFlowsToByAnalysed) {
//            stF.printStatusFlow("Database old flows");
//        }
        
        /*
         *  Join old flows from database to current flows from the memory in a list!
         *  This list have all current flows registered in memory (currentFlows list)
         *  and the flows from now until some seconds ago (timePeriodToRecoverFlowFromDB). 
         */
        for (String key : SensorOpenFlow.currentFlows.keySet()) {
            StatusFlow currentFlow = SensorOpenFlow.currentFlows.get(key);
            currentFlow.setInSwitchesMemory(true);
            allFlowsToByAnalysed.add(currentFlow);
        }
        
//        for(StatusFlow stF: allFlowsToByAnalysed) {
//            stF.printStatusFlow("Old and current flows:");
//        }
        
       
        // Store all flows that are suspicious of DDoS
        FlowsSuspiciousOfDoS flowSuspiciousOfDDoS = new FlowsSuspiciousOfDoS();
        
        // Processes all current flows in network switches        
        for (StatusFlow currentFlow : allFlowsToByAnalysed) {
            /*
             * Verify if this flow have few packets (<=3)! if this is true, then we
             * consider suspicious.
             * 
             * This list have all current flows registered in memory (currentFlows list)
             * and the flows from now until some seconds ago (timePeriodToRecoverFlowFromDB). 
             * 
             * And protocol is equal 6 (TCP)
             * TODO - verify others protocols!
             * 
             * 120 just TCP header!
             * 
             */
            if(currentFlow.getPacketCount() <= 2 && currentFlow.getNetworkProtocol()==6 && currentFlow.getByteCount()<=120) {
                // Save this current and suspect flow.
                flowSuspiciousOfDDoS.putAlertsFlowOnListOfRelatedWithThisConnection(currentFlow);
            }
            
            /*
             * 
             * Here, we can put others identification methods to DoS attacks!
             *
             * IDEA - to UDP, and ICMP control the time! like 5 seconds with just only 5 packets!
             * If we implement this we must put the above verification <=5 to only the TCP flows...
             * 
             */
        }
        
        if(flowSuspiciousOfDDoS.isDanger()) {
            listOfMaliciousFlows.addAll(flowSuspiciousOfDDoS.getFlowsRelatedWithThisConnection());
            flowSuspiciousOfDDoS.printStatistics();
        }
        
        AlertOpenFlowDAO aletOpenFlowDAO = new AlertOpenFlowDAO();
        for(AlertMessageSharePriority alertMessageSharePriority : listOfMaliciousFlows) {
            aletOpenFlowDAO.insert(alertMessageSharePriority);
        }

    }
    
    /**
     * Looking for DoS attacks using IP source! This is made analyzing the number of connections
     * from a source network address (IP) and the low number of packets
     * transmitted by his related flows.
     * 
     * TODO - For now it's just to prove that is possible use the OpenFlow to
     * mitigate suspects flow! In the future, new methods should be
     * implemented....
     */
    public void analyzeDoSAttackUsingIPSource_Old() {
        // Remove all old messages present in the list of malicious flows to do a new list!
        listOfMaliciousFlows.clear();
        
        /*
         * This hash map is used to store the source network address (IP)
         * related with a ConexaoDDoS (DDoS connection) class. The ConexaoDDoS
         * class extends MensagemAlerta (Alert Message) class.
         */
        HashMap<Integer, FlowsSuspiciousOfDoS> listOfAnalyzedSourceAddress = new HashMap<Integer, FlowsSuspiciousOfDoS>();
        /*
         * The OpenFlow flows are split here, the current flows that are
         * currently installed on network switches have your flows logged in the
         * currentFlows list, and flows that had already his flows removed from
         * network switches has this flows registered on the database. In other
         * words, current flows are in memory and old flows are in database.
         */

        // Get old flows from database!
        List<StatusFlow> allFlowsToByAnalysed = new ArrayList<StatusFlow>();
        try {
            StatusFlowDAO statusFlowDAO = new StatusFlowDAO();
            // TODO - What time period is better to use?
            allFlowsToByAnalysed =  statusFlowDAO.getList_GoodBadFlows_upToSecondsAgo(this.timePeriodToRecoverFlowFromDB);
            log.debug("Number of alert valid alerts from database: {}", allFlowsToByAnalysed.size());
        } catch (ClassNotFoundException e) {
            log.debug("ATTENTION - Sorry wasn't possible to read data in database - SQL error!");
            e.printStackTrace();
        } catch (SQLException e) {
            log.debug("ATTENTION - Error during SQL select from flows table!");
            e.printStackTrace();
        }
        
        // print selected flow from database
//        for(StatusFlow stF: allFlowsToByAnalysed) {
//            stF.printStatusFlow("Database old flows");
//        }
        
        /*
         *  Join old flows from database to current flows from the memory in a list!
         *  This list have all current flows registered in memory (currentFlows list)
         *  and the flows from now until some seconds ago (timePeriodToRecoverFlowFromDB). 
         */
        for (String key : SensorOpenFlow.currentFlows.keySet()) {
            StatusFlow currentFlow = SensorOpenFlow.currentFlows.get(key);
            allFlowsToByAnalysed.add(currentFlow);
        }
        
//        for(StatusFlow stF: allFlowsToByAnalysed) {
//            stF.printStatusFlow("Old and current flows:");
//        }
        
       
        // Store all flows that are suspicious of DDoS
        FlowsSuspiciousOfDoS flowSuspiciousOfDDoS = new FlowsSuspiciousOfDoS();
        
        // Processes all current flows in network switches        
        for (StatusFlow currentFlow : allFlowsToByAnalysed) {
             saveSuspiciousDoSByIPSource(listOfAnalyzedSourceAddress, currentFlow);
            
        }
         verifyDoSBySourceIP(listOfAnalyzedSourceAddress);
    }
    

    /**
     * Verify if suspicious flows obtained in by saveSuspiciousDoSByIPSource method, really have any attack DoS.
     * @param listOfAnalyzedSourceAddress
     */
    private void verifyDoSBySourceIP(
            HashMap<Integer, FlowsSuspiciousOfDoS> listOfAnalyzedSourceAddress) {
        /*
         * At this point we have all suspicious flow, separated by source
         * network address! Then, we will consider malicious flow, source
         * address that have many flows with few packets in each flow! We will
         * send all discovered malicious flows to be processed, like security
         * alerts, by the memory attacks class and his itemsets algorithms.
         */
        // Process each source address to verify if this is have malicious flows or not!
        for (Integer key : listOfAnalyzedSourceAddress.keySet()) {
            FlowsSuspiciousOfDoS flowsSuspiciousOfDoS = listOfAnalyzedSourceAddress.get(key);
            flowsSuspiciousOfDoS.printStatistics();
            // aqui
            /*
             * Set ALL alertMessageSharePriority objects with the general alert
             * priority from this source network address group! But we going to
             * looking just to alerts from this source address, not all... This
             * will avoid a loop for each alert from this group!
             */
            flowsSuspiciousOfDoS.setALLAlertMessageSharePriorityObjectsWithThisGeneralPriority();
            
            // Verify if this source network address have malicious flows!
            if (flowsSuspiciousOfDoS.isDanger()) {
                // If yes, stores to be processed by MemorysAttacks itemsets algorithm.
                listOfMaliciousFlows.addAll(flowsSuspiciousOfDoS.getFlowsRelatedWithThisConnection());
            }
            //flowsSuspiciousOfDoS.printFlowsRelated();
        }
    }


    /**
     * Just save IP sources that have suspicious of DoS attack.
     * @param listOfAnalyzedSourceAddress
     * @param currentFlow
     * @param suspiciousFlow
     */
    private void saveSuspiciousDoSByIPSource(
            HashMap<Integer, FlowsSuspiciousOfDoS> listOfAnalyzedSourceAddress,
            StatusFlow currentFlow) {
     // Used to store the number of connections from a source network address.
        FlowsSuspiciousOfDoS suspiciousFlow = new FlowsSuspiciousOfDoS();
        /*
         * Verify if this flow have few packets (<=5) and if this flow is
         * related to a known port (<=1024)! if this is true, then we
         * consider suspicious.
         * 
         * This list have all current flows registered in memory (currentFlows list)
         * and the flows from now until some seconds ago (timePeriodToRecoverFlowFromDB). 
         * 
         */
        if(currentFlow.getPacketCount() <= 5 && currentFlow.getTransportDestination()<=1024) {
            if(listOfAnalyzedSourceAddress.containsKey(currentFlow.getNetworkSource())) {
                // Yes, we already have an entry for this network source address on listOfAnalyzedSourceAddress list.
                // Take it!
                suspiciousFlow = listOfAnalyzedSourceAddress.get(currentFlow.getNetworkSource());
                
                // Increment the number of suspicious connections and set the new number!
                suspiciousFlow.putAlertsFlowOnListOfRelatedWithThisConnection(currentFlow);                            
            }else {
                /*
                 * No, we didn't had this source network address in the listOfAnalyzedSourceAddress
                 * list, therefore, create an object for this!
                 */
                suspiciousFlow.putAlertsFlowOnListOfRelatedWithThisConnection(currentFlow);
                
                /*
                 * Insert all this on the list of analyze source network
                 * address! This will be used in the end to decide if an
                 * flow is malicious or not! if is malicious we go take the
                 * related alerts flows and send it to be processed by
                 * memory of attacks.
                 */
                listOfAnalyzedSourceAddress.put(currentFlow.getNetworkSource(), suspiciousFlow);
            }
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
     * Don't use this, now we use the database!
     * @return
     */
    public List<AlertMessageSharePriority> getListOfMaliciousFlows() {
        return listOfMaliciousFlows;
    }
    

}
