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
     * @return - Itemsets string of status flows.
     */
    public String getItemsetsString_ofAllAlerts(String comment) {
     // Strings to store both results: IDS and Analysis flow.
        String alertsFromIDSSnort = "";
        String alertsFromOpenFlowDoS = "";
        // Get IDS alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseIDSAlerts != 1) {
            alertsFromIDSSnort = ids.getItemsetsString_ofAllAlerts(comment);
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS_UseIDSAlerts on LearningSwithTutorialSolution class...");
        }
        
        // Get OpenFlow alerts.
        if (LearningSwitchTutorialSolution.disableOfIDPS_UseOfAlerts != 1
                && LearningSwitchTutorialSolution.disableOfIDPS_UseOfgetStatisticsFromNetwork != 1) {
            //alertsFromOpenFlowDoS = alertOpenFlowDAO.getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(timeToAlertsStayOnMemory, comment);
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variables disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
        }
        return alertsFromIDSSnort+alertsFromOpenFlowDoS;
        
    }
    
    // 2
    
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
            alertsFromOpenFlowDoS = alertOpenFlowDAO.getItemsetsStringFromOpenFlowAlertsUpToSecondsAgo(timeToAlertsStayOnMemory, comment);
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
            listOfAllAlerts.addAll(alertOpenFlowDAO.getOpenFlowAlertsUpToSecondsAgo(timeToAlertsStayAtMemory, comment));
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variables disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
        }
        
        return listOfAllAlerts;
        
    }

}
