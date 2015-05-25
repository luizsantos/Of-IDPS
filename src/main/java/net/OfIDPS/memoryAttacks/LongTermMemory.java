package net.OfIDPS.memoryAttacks;

import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import net.beaconcontroller.DAO.AlertOpenFlowDAO;
import net.beaconcontroller.DAO.StatusFlowDAO;
import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.IntrusionPreventionSystem;
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tools.FileManager;
import net.beaconcontroller.tutorial.ActuatorOpenFlow;
import net.beaconcontroller.tutorial.CONFIG;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LongTermMemory extends Thread {
    
    protected IBeaconProvider beaconProvider;
    
    // To bad remembrances - long bad memory.
    private Map<String,AlertMessage> longMemoryAttacks;
    
    // To good remembrances - long good memory.
    private Map<String, AlertMessage> longMemoryForGoodRemembrances;
    
    // Method to recover remembrances to long memory.
    // Get all remembrances - this can consume a lot of the machine process.
    public static final int recoverRemembrancesUsing_1_getAll=1;
    // Get remembrances using a limit to recovery the database register, example get the last 10.000 registers.
    public static final int recoverRemembrancesUsing_2_getLastUsingLimit=2;
    // Get remembrances using a limit but get the registers randomly.
    public static final int recoverRemembrancesUsing_2_1_getRandomlyUsingLimit=3;
    /*
     * Get remembrances using a limit but get the registers randomly and using a 
     * statistic threshold based on the amount of existent registers in database 
     * to generate reliable samples.
     */
    public static final int recoverRemembrancesUsing_2_2_getStatisticUsingLimit=4;
    // Get remembrances up to seconds ago. 
    public static final int recoverRemembrancesUsing_3_getFromSecondsAgo=5;
    // Get remembrances up to seconds ago but get the registers randomly.
    public static final int recoverRemembrancesUsing_3_1_getRandomlyFromSecondsAgo=6;
    /*
     * Get remembrances up to seconds ago but get the registers randomly and using a 
     * statistic threshold based on the amount of existent registers in database 
     * to generate reliable samples.
     */
    public static final int recoverRemembrancesUsing_3_2_getStatisticFromSecondsAgo=7;
    private static int methodToRecoverRemembrancesToLongMemory = recoverRemembrancesUsing_3_getFromSecondsAgo; 
    
    // Max number of registers to be recovered from database;
    private static int limit_to_recover_databaseFlows=10000;
    
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    /*
     * Time to wait until execute again the main method contained in the Thread (method run).
     */
    public static final int TIME_TO_WAIT= 3;
    
    /**
     * Startup method, you must use this before of run the start thread method (run/start).
     * @param bP - beacon for use the actuator.
     * @param longMemoryAttacks - long bad memory.
     * @param longMemoryForGoodRemembrances - long good memory.
     */
    public void startUp(
            IBeaconProvider bP, 
            Map<String,AlertMessage> longMemoryAttacks,
            Map<String, AlertMessage> longMemoryForGoodRemembrances) {
        this.beaconProvider = bP;
        this.longMemoryAttacks = longMemoryAttacks;
        this.longMemoryForGoodRemembrances=longMemoryForGoodRemembrances;
    }

    /**
     * 
     * Method responsible to run the Thread and send OpenFlow statistics messages request.
     * 
     */
    public void run() {
        log.debug("Start Thread that is responsible to construct Long-Term memory.");
        while (true) {
            if (MemorysAttacks.disableLongMemory != 1) {
                
                // To use memoryAttacks methods.
                MemorysAttacks memoryAttacks = new MemorysAttacks();
                
                if (MemorysAttacks.disableLongGoodMemory != 1) {
                    // Run memory for good remembrances.
                    longGoodMemory(memoryAttacks);
                } else {
                    log.debug("\t!!!!!!!! ATTENTION, Long GOOD memory is DISABLED!!!!!!!!  to change this setup to 0 (zero) the variable disableLongGoodMemory on MemoryAttacks class...");
                }
                
                if (MemorysAttacks.disableLongBadMemory != 1) {
                    // Run memory for bad remembrances.
                    longBadMemory(memoryAttacks);
                } else {
                    log.debug("\t!!!!!!!! ATTENTION, Long BAD memory is DISABLED!!!!!!!!  to change this setup to 0 (zero) the variable disableLongBadMemory on MemoryAttacks class...");
                }
                
            } else {
                log.debug("\t!!!!!!!! ATTENTION, LONG memory is DISABLED (bad and good)!!!!!!!!  to change this setup to 0 (zero) the variable disableLongMemory on MemoryAttacks class...");
            }
            // Time to waiting
            log.debug("Waiting {} seconds to rerun Long-term memory", TIME_TO_WAIT);
            waitTimeInSeconds(TIME_TO_WAIT);
            
        }
        
    }

    /**
     * Perform long-term memory methods to recovery bad remembrances.
     * 
     * @param ids - An IntrusionPreventionSystem object to recover IDS alerts.
     * @param alertOpenFlowDAO - An AlertOpenFlowDAO object to recover OpenFlow alerts.
     * @param memoryAttacks - To execute some memory attacks methods.
     */
    private void longBadMemory(MemorysAttacks memoryAttacks) {
        log.debug("Long-term Bad Memory");
        Date dateStart = DateTimeManager.getCurrentDate();
        
        // To recover alerts from IDS.
        IntrusionPreventionSystem ids = new IntrusionPreventionSystem();
        // To recover alerts from OpenFlow statistics.
        AlertOpenFlowDAO alertOpenFlowDAO = new AlertOpenFlowDAO();
        
        
        // Get alerts from IDS and OpenFlow analysis to be processed by itemsets algorithm.
        String allAlerts = memoryAttacks.getAlertsFromIDSAndOpenFlowAnalysisToBeProcessedByItemsetsAlgorithm(
                ids, 
                alertOpenFlowDAO,
                MemorysAttacks.timeToAlertsStayAtLongMemory,
                "Long memory");
        
        //log.debug("all alerts in long memory: \n{}", allAlerts);
        
        // Obtain rules from IDS alerts using itemsets algorithm.
        Map<String,AlertMessage> ruleListFromIDS = new HashMap<String, AlertMessage>();
        ruleListFromIDS = memoryAttacks.getSecurityRulesUsingItensetsAlgorithm(allAlerts);
        
        longMemoryAttacks.clear();
        longMemoryAttacks.putAll(ruleListFromIDS);
        
        // Start the actuator module to remove bad flows from the network.
        /*
         * The actuator from long memory is used to remove bad 
         * flows presents on the long memory. 
         */
        if (ruleListFromIDS.size() > 0) {
            ActuatorOpenFlow actuatorFromSensorialMemory = new ActuatorOpenFlow();
            actuatorFromSensorialMemory.startUp(beaconProvider);
            actuatorFromSensorialMemory.deleteAllFlowUsingCampsPresentsMemoryRulesInAllSwitches(ruleListFromIDS);
            actuatorFromSensorialMemory.shutDown();
        }
        
        printRules(ruleListFromIDS, "Bad memory.");
        
        
        Date dateStop = DateTimeManager.getCurrentDate();
        long diffSeconds = DateTimeManager.differenceBetweenTwoDatesInSeconds(dateStart, dateStop);
        log.debug("End of LONG memory! {} - {} -> {} seconds", 
                DateTimeManager.dateToStringJavaDate(dateStart), 
                DateTimeManager.dateToStringJavaDate(dateStop),
                diffSeconds);
        
    }

    
    
    /**
     * Perform long-term memory methods to recovery bad remembrances.
     * 
     * @param ids - An IntrusionPreventionSystem object to recover IDS alerts.
     * @param alertOpenFlowDAO - An AlertOpenFlowDAO object to recover OpenFlow alerts.
     * @param memoryAttacks - To execute some memory attacks methods.
     */
    private void longGoodMemory(MemorysAttacks memoryAttacks) {
        log.debug("Long-term Good Memory");
        Date dateStart = DateTimeManager.getCurrentDate();
        String allGoodFlows = "";

        // Get good network flows that were not related with security alerts.
        try {
            StatusFlowDAO statusFlowDAO = new StatusFlowDAO();
            switch(methodToRecoverRemembrancesToLongMemory){
                case LongTermMemory.recoverRemembrancesUsing_1_getAll:
                    log.debug("Get all good remembrances!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_1_allFlows();
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_getLastUsingLimit:
                    log.debug("Get last good remembrances using a limit!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_2_lastUsingLimit(limit_to_recover_databaseFlows);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_1_getRandomlyUsingLimit:
                    log.debug("Get randomly good remembrances using a limit!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_2_1_randomlyUsingLimit(limit_to_recover_databaseFlows);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_2_getStatisticUsingLimit:
                    log.debug("Get randomly using statistical parameters the last good remembrances using a limit!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_2_2_getStatisticUsingLimit();
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_getFromSecondsAgo:
                    log.debug("Get last good remembrances up to seconds ago!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_3_upToSecondsAgo(MemorysAttacks.timeToAlertsStayAtLongMemory);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_1_getRandomlyFromSecondsAgo:
                    log.debug("Get randomly last good remembrances up to seconds ago!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_3_1_randomlyFromSecondsAgo(
                            MemorysAttacks.timeToAlertsStayAtLongMemory, limit_to_recover_databaseFlows);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_2_getStatisticFromSecondsAgo:
                    log.debug("Get randomly using statistical parameters the last good remembrances up to seconds ago!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_3_2_getStatisticFromSecondsAgo(MemorysAttacks.timeToAlertsStayAtLongMemory);
                    break;
                default:
                    log.debug("Default - Get last good remembrances using a limit!");
                    statusFlowDAO.getItemsetsString_ofNormalFlows_2_lastUsingLimit(limit_to_recover_databaseFlows);
            }
            
        } catch (ClassNotFoundException e) {
            log.debug("Error to create StatusFlowDAO on good LongTermMemory class.");
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SQLException e) {
            log.debug("SQL error to create StatusFlowDAO on good LongTermMemory class.");
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        // Obtain rules from IDS alerts using itemsets algorithm.
        Map<String,AlertMessage> ruleListFromIDS = new HashMap<String, AlertMessage>();
        ruleListFromIDS = memoryAttacks.getSecurityRulesUsingItensetsAlgorithm(allGoodFlows);
        
        longMemoryForGoodRemembrances.clear();
        longMemoryForGoodRemembrances.putAll(ruleListFromIDS);
        
        //printRules(ruleListFromIDS, "Good memory.");
        FileManager fileManager = new FileManager("~", "goodMemory.txt");
        fileManager.writeFile(allGoodFlows);
        
        Date dateStop = DateTimeManager.getCurrentDate();
        long diffSeconds = DateTimeManager.differenceBetweenTwoDatesInSeconds(dateStart, dateStop);
        log.debug("End of GOOD long memory! {} - {} -> {} seconds", 
                DateTimeManager.dateToStringJavaDate(dateStart), 
                DateTimeManager.dateToStringJavaDate(dateStop),
                diffSeconds);
    }
    
    /**
     * Print the list of rules;
     * @param ruleListFromIDS - Rule list;
     */
    private void printRules(Map<String, AlertMessage> ruleListFromIDS, String comment) {
        log.debug("{} of rules {} memory", ruleListFromIDS.size(), comment);
        for(String key : ruleListFromIDS.keySet()) {
            AlertMessage goodFlow = ruleListFromIDS.get(key);
            goodFlow.printMsgAlert();
        }
    }
    
    /**
     * Waiting a period of seconds 
     * 
     * @param timeInSeconds
     *            the Thread will wait a period of time.
     */
    private void waitTimeInSeconds(int timeInSeconds) {
        try {
            sleep(timeInSeconds * 1000);
        } catch (InterruptedException e) {
            log.debug("Problem with sleep in LongTermMemory:waitTimeInSeconds");
            e.printStackTrace();
        }
    }

}
