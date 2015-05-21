package net.OfIDPS.memoryAttacks;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import net.beaconcontroller.DAO.AlertOpenFlowDAO;
import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.IPS.IntrusionPreventionSystem;
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tutorial.ActuatorOpenFlow;
import net.beaconcontroller.tutorial.CONFIG;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LongTermMemory extends Thread {
    
    protected IBeaconProvider beaconProvider;
    
    private Map<String,AlertMessage> longMemoryAttacks;
    
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    /*
     * Time to wait until execute again the main method contained in the Thread (method run).
     */
    public static final int TIME_TO_WAIT= 3;
    
    public void startUp(IBeaconProvider bP, Map<String,AlertMessage> longMemoryAttacks) {
        this.beaconProvider = bP;
        this.longMemoryAttacks = longMemoryAttacks;
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
                longBadMemory();
            } else {
                log.debug("\t!!!!!!!! ATTENTION, Long memory is DISABLED!!!!!!!!  to change this setup to 0 (zero) the variable disableLongMemory on MemoryAttacks class...");
            }
            // Time to waiting
            log.debug("Waiting {} seconds to rerun Long-term memory", TIME_TO_WAIT);
            waitTimeInSeconds(TIME_TO_WAIT);
            
        }
        
    }

    private void longBadMemory() {
        log.debug("Long-term Memory");
        Date dateStart = DateTimeManager.getCurrentDate();
        
        // To recover alerts from IDS.
        IntrusionPreventionSystem ids = new IntrusionPreventionSystem();
        // To recover alerts from OpenFlow statistics.
        AlertOpenFlowDAO alertOpenFlowDAO = new AlertOpenFlowDAO();
        // To use memoryAttacks methods.
        MemorysAttacks memoryAttacks = new MemorysAttacks();
        
        // Get alerts from IDS and OpenFlow analysis to be processed by itemsets algorithm.
        String allAlerts = memoryAttacks.getAlertsFromIDSAndOpenFlowAnalysisToBeProcessedByItemsetsAlgorithm(
                ids, 
                alertOpenFlowDAO,
                MemorysAttacks.timeToAlertsStayAtLongMemory,
                "Long memory");
        
        //log.debug("all alerts in long memory: \n{}", allAlerts);
        
        // Obtain rules from IDS alerts using itemsets algorithm.
        Map<String,AlertMessage> ruleListFromIDS = new HashMap<String, AlertMessage>();
        ruleListFromIDS = memoryAttacks.getRulesFromIDSAlertsUsingItensetsAlgorithm(allAlerts);
        
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
        
        
        Date dateStop = DateTimeManager.getCurrentDate();
        long diffSeconds = DateTimeManager.differenceBetweenTwoDatesInSeconds(dateStart, dateStop);
        log.debug("End of LONG memory! {} - {} -> {} seconds", 
                DateTimeManager.dateToStringJavaDate(dateStart), 
                DateTimeManager.dateToStringJavaDate(dateStop),
                diffSeconds);
        
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
