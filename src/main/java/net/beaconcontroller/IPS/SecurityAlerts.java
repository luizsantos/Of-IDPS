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
import net.beaconcontroller.tutorial.CONFIG;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

public class SecurityAlerts {
    
    // To recover alerts from IDS
    private IntrusionPreventionSystem ids = new IntrusionPreventionSystem();
    // To recover alerts from OpenFlow statistics
    private AlertOpenFlowDAO alertOpenFlowDAO = new AlertOpenFlowDAO();

    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
        
    /**
     * Get itemset string from security alerts using a method to retrieve them.
     * Even that the method chosen not use limit or seconds you must pass both.
     * If you don't know who time or limit to use, because you don't you use it,
     *  you can use to limit the attribute: 
     *  - limit_to_recover_databaseFlows from LongTermMemory class, 
     * and to seconds: 
     *  - timeToAlertsStayAtSensorialMemory from MemorysAttacks.
     * 
     * 
     * @param limit - Amount of register to be returned.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - Itemsets string of alerts.
     */
    public String getItemsetsString_FromAlerts(
            int methodToRecoverRemembrancesToLongMemory, 
            int limit, 
            int seconds, 
            String stringWhoCalled) {
        // Strings to store both results: IDS and Analysis flow.
        String alertsFromIDSSnort = "";
        String alertsFromOpenFlow = "";
        // Get IDS alerts.
        if (CONFIG.DISABLE_OFIDPS_EXTERNAL_IDS != 1) {
            switch(methodToRecoverRemembrancesToLongMemory){
                case LongTermMemory.recoverRemembrancesUsing_1_getAll:
                    //log.debug("{} - Get all Snort alerts!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_1_allFlows(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_getLastUsingLimit:
                    //log.debug("{} - Get last Snort alerts using a limit!", , stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_lastUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_1_getRandomlyUsingLimit:
                    //log.debug("{} - Get randomly Snort alerts using a limit!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_1_randomlyUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_2_getStatisticUsingLimit:
                    //log.debug("{} - Get randomly using statistical parameters the last Snort alerts using a limit!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_2_getStatisticUsingLimit(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_getFromSecondsAgo:
                    //log.debug("{} - Get last Snort alerts up to seconds ago!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_3_UpToSecondsAgo(seconds, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_1_getRandomlyFromSecondsAgo:
                    //log.debug("{} - Get randomly last Snort alerts up to seconds ago!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_3_1_randomlyFromSecondsAgo(seconds, limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_2_getStatisticFromSecondsAgo:
                    //log.debug("{} - Get randomly using statistical parameters the Snort alerts up to seconds ago!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_3_2_getStatisticFromSecondsAgo(seconds, stringWhoCalled);
                    break;
                default:
                    log.debug("{} - Default - Get bad good remembrances using a limit!", stringWhoCalled);
                    alertsFromIDSSnort=ids.getItemsetsString_SnortAlerts_2_lastUsingLimit(limit, stringWhoCalled);
            } 
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED," +
            		" then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!" +
            		"  to change this setup to 0 (zero) the variable DISABLE_OFIDPS_EXTERNAL_IDS on CONFIG class...");
        }
        
        // Get OpenFlow alerts.
        if (CONFIG.DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS != 1
                && CONFIG.DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK != 1) {
            switch(methodToRecoverRemembrancesToLongMemory){
                case LongTermMemory.recoverRemembrancesUsing_1_getAll:
                    //log.debug("{} - Get all bad remembrances!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_1_All(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_getLastUsingLimit:
                    //log.debug("{} - Get last bad remembrances using a limit!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_lastUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_1_getRandomlyUsingLimit:
                    //log.debug("{} - Get randomly bad remembrances using a limit!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_1_randomlyUsingLimit(limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_2_2_getStatisticUsingLimit:
                    //log.debug("{} - Get randomly using statistical parameters the last bad remembrances using a limit!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_2_getStatisticUsingLimit(stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_getFromSecondsAgo:
                    //log.debug("{} - Get last bad remembrances up to seconds ago!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_UpToSecondsAgo(seconds, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_1_getRandomlyFromSecondsAgo:
                    //log.debug("{} - Get randomly last bad remembrances up to seconds ago!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_1_randomlyFromSecondsAgo(seconds, limit, stringWhoCalled);
                    break;
                case LongTermMemory.recoverRemembrancesUsing_3_2_getStatisticFromSecondsAgo:
                    //log.debug("{} - Get randomly using statistical parameters the last bad remembrances up to seconds ago!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_3_2_getStatisticFromSecondsAgo(seconds, stringWhoCalled);
                    break;
                default:
                    log.debug("{} - Default - Get bad good remembrances using a limit!", stringWhoCalled);
                    alertsFromOpenFlow = alertOpenFlowDAO.getItemsetsString_OpenFlowAlerts_2_lastUsingLimit(limit, stringWhoCalled);
            }
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED," +
            		" then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!" +
            		"  to change this setup to 0 (zero) the variables DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS" +
            		" and DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK on CONFIG class...");
        }
        return alertsFromIDSSnort+alertsFromOpenFlow;
    }
    
        
    
    /**
     * Get list of alerts from now up to seconds ago.
     * @param seconds - Amount of seconds that will be used as period of time between the current time.
     * @param stringWhoCalled - Just a commentary to identification.
     * @return - A list of alerts.
     */
    public List<AlertMessage> getList_alerts_upToSecondsAgo(int seconds, String stringWhoCalled) {
        // To store all alerts.
        List<AlertMessage> listOfAllAlerts =  new ArrayList<AlertMessage>();
        
        // Verify if IDS is enabled.
        if (CONFIG.DISABLE_OFIDPS_EXTERNAL_IDS != 1) {
            // Get alerts from IDS using the time of memory.
            listOfAllAlerts.addAll(ids.getAlertsFromSnortIDS(seconds, stringWhoCalled));
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS IDS alerts analysis IS DISABLED," +
            		" then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!" +
            		"  to change this setup to 0 (zero) the variable DISABLE_OFIDPS_EXTERNAL_IDS on CONFIG class...");
        }
        
        //Verify if the OpenFlow security analysis is enabled.
        if (CONFIG.DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS != 1
                && CONFIG.DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK != 1) {
            listOfAllAlerts.addAll(alertOpenFlowDAO.getList_OpenFlowAlerts_3_UpToSecondsAgo(seconds, stringWhoCalled));
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED," +
            		" then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!" +
            		"  to change this setup to 0 (zero) the variables DISABLE_OFIDPS_ANALYSE_SECURITY_USING_OPENFLOW_STATISTICS" +
            		" and DISABLE_OFIDPS_GET_OPENFLOW_STATISTICS_FROM_NETWORK on CONFIG class...");
        }
        
        return listOfAllAlerts;
        
    }

}
