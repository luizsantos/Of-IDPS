/**
 * To concentrate all alerts (IDS - Snort, Bro, etc and OpenFlow).
 * 
 * TODO - For now, it's only concentrate the alert read, but is 
 * interesting to concentrate all methods including write.
 * 
 */
package net.beaconcontroller.IPS;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.OfIDPS.memoryAttacks.LongTermMemory;
import net.beaconcontroller.DAO.AlertOpenFlowDAO;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

public class SecurityAlerts {
    
    // To recover alerts from IDS
    private IntrusionPreventionSystem ids = new IntrusionPreventionSystem();
    // To recover alerts from OpenFlow statistics
    private AlertOpenFlowDAO alertOpenFlowDAO = new AlertOpenFlowDAO();

    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    // 1
    
    /**
     * Get itemset string from all normal flows.
     * 
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of alerts.
     */
    public String getItemsetsString_Alerts_1_all(String stringWhoCalled) {
     // Strings to store both results: IDS and Analysis flow.
        String alertsFromIDSSnort = "";
        String alertsFromOpenFlowDoS = "";
        // Get IDS alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseIDSAlerts != 1) {
            alertsFromIDSSnort = ids.getItemsetsString_SnortAlerts_1_allFlows(stringWhoCalled);
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS_UseIDSAlerts on LearningSwithTutorialSolution class...");
        }
        
        // Get OpenFlow alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseOfAlerts != 1
                && LearningSwitchTutorialSolution.disableOfIDPS_UseOfgetStatisticsFromNetwork != 1) {
            //alertsFromOpenFlowDoS = alertOpenFlowDAO.getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(timeToAlertsStayOnMemory, comment);
            // TODO - make it!
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variables disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
        }
        return alertsFromIDSSnort+alertsFromOpenFlowDoS;   
    }
    
    // 2
    
    /**
     * Get itemset string from from last alerts using a limit number of register to be retrieved.
     * 
     * @param limit - Amount of register to be returned.
     * @param stringWhoCalled - Just a commentary to identification .
     * @return - Itemsets string of alerts.
     */
    public String getItemsetsString_FromAlerts(int methodToRecoverRemembrancesToLongMemory, int limit, int seconds, String stringWhoCalled) {
        // Strings to store both results: IDS and Analysis flow.
        String alertsFromIDSSnort = "";
        String alertsFromOpenFlow = "";
        // Get IDS alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseIDSAlerts != 1) {
            switch(methodToRecoverRemembrancesToLongMemory){
                case LongTermMemory.recoverRemembrancesUsing_1_getAll:
                    log.debug("Get all Snort alerts!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_1_allFlows(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_getLastUsingLimit:
                    log.debug("Get last Snort alerts using a limit!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_lastUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_1_getRandomlyUsingLimit:
                    log.debug("Get randomly Snort alerts using a limit!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_1_randomlyUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_2_getStatisticUsingLimit:
                    log.debug("Get randomly using statistical parameters the last Snort alerts using a limit!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_2_getStatisticUsingLimit(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_getFromSecondsAgo:
                    log.debug("Get last Snort alerts up to seconds ago!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_3_UpToSecondsAgo(seconds, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_1_getRandomlyFromSecondsAgo:
                    log.debug("Get randomly last Snort alerts up to seconds ago!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_3_1_randomlyFromSecondsAgo(seconds, limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_2_getStatisticFromSecondsAgo:
                    log.debug("Get randomly using statistical parameters the Snort alerts up to seconds ago!");
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_3_2_getStatisticFromSecondsAgo(seconds, stringWhoCalled);
                    break;
                default:
                    log.debug("Default - Get bad good remembrances using a limit!");  
            } 
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS_UseIDSAlerts on LearningSwithTutorialSolution class...");
        }
        
        // Get OpenFlow alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseOfAlerts != 1
                && LearningSwitchTutorialSolution.disableOfIDPS_UseOfgetStatisticsFromNetwork != 1) {
            switch(methodToRecoverRemembrancesToLongMemory){
                case LongTermMemory.recoverRemembrancesUsing_1_getAll:
                    log.debug("Get all bad remembrances!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_1_All(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_getLastUsingLimit:
                    log.debug("Get last bad remembrances using a limit!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_lastUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_1_getRandomlyUsingLimit:
                    log.debug("Get randomly bad remembrances using a limit!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_1_randomlyUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_2_getStatisticUsingLimit:
                    log.debug("Get randomly using statistical parameters the last bad remembrances using a limit!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_2_getStatisticUsingLimit(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_getFromSecondsAgo:
                    log.debug("Get last bad remembrances up to seconds ago!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_UpToSecondsAgo(seconds, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_1_getRandomlyFromSecondsAgo:
                    log.debug("Get randomly last bad remembrances up to seconds ago!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_1_randomlyFromSecondsAgo(seconds, limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_2_getStatisticFromSecondsAgo:
                    log.debug("Get randomly using statistical parameters the last bad remembrances up to seconds ago!");
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_2_getStatisticFromSecondsAgo(seconds, stringWhoCalled);
                    break;
                default:
                    log.debug("Default - Get bad good remembrances using a limit!");
                    
            }
            //alertsFromOpenFlowDoS = alertOpenFlowDAO.getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(timeToAlertsStayOnMemory, comment);
            // TODO - make it!
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variables disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
        }
        return alertsFromIDSSnort+alertsFromOpenFlow;
        
    }
    
    
    // 3
    
    // Others:
    
    
    /**
     * Get both alerts: IDS and OpenFlow.
     * 
     * @param timeToAlertsStayOnMemory - It is the time of the memory that will be processed. e.g. time of short or long memory.
     * @param comment - Just a commentary text to identify for example the type of memory that is in use.
     * @return - A string ready to be processed by the itemsets algorithm.
     */
    public String getItemsetsString_Alerts_upToSecondsAgo(
            int timeToAlertsStayOnMemory,
            String comment) {
        
        // Strings to store both results: IDS and Analysis flow.
        String alertsFromIDSSnort = "";
        String alertsFromOpenFlowDoS = "";
        
        // Get IDS alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseIDSAlerts != 1) {
            alertsFromIDSSnort = ids.getItemsetsString_SnortAlerts_upToSecondsAgo(timeToAlertsStayOnMemory, comment);
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS_UseIDSAlerts on LearningSwithTutorialSolution class...");
        }
        
        // Get OpenFlow alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseOfAlerts != 1
                && LearningSwitchTutorialSolution.disableOfIDPS_UseOfgetStatisticsFromNetwork != 1) {
            alertsFromOpenFlowDoS = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_UpToSecondsAgo(timeToAlertsStayOnMemory, comment);
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variables disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
        }
        
        // Join alerts
        return alertsFromIDSSnort + alertsFromOpenFlowDoS;
    }
    
    
    /**
     * 
     * @param timeToAlertsStayAtMemory
     * @param comment
     * @return
     */
    public List<AlertMessage> getList_alerts_upToSecondsAgo(int timeToAlertsStayAtMemory, String comment) {
        // To store all alerts.
        List<AlertMessage> listOfAllAlerts =  new ArrayList<AlertMessage>();
        
        // Verify if IDS is enabled.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseIDSAlerts != 1) {
            // Get alerts from IDS using the time of memory.
            listOfAllAlerts.addAll(ids.getAlertsFromSnortIDS(timeToAlertsStayAtMemory, comment));
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS_UseIDSAlerts on LearningSwithTutorialSolution class...");
        }
        
        //Verify if the OpenFlow security analysis is enabled.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseOfAlerts != 1
                && LearningSwitchTutorialSolution.disableOfIDPS_UseOfgetStatisticsFromNetwork != 1) {
            listOfAllAlerts.addAll(alertOpenFlowDAO.getList_OpenFlowAlerts_3_UpToSecondsAgo(timeToAlertsStayAtMemory, comment));
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variables disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
        }
        
        return listOfAllAlerts;
        
    }

}
