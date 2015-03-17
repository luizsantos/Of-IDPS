/**
 * Used to store suspicious flows from the same network source.
 * 
 * In the past: Used to store suspicious flows from the same network source, but now we control any suspicious flows
 * and not more only by source IP.
 *  
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com 
 */
package net.beaconcontroller.IPS;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.DAO.StatusFlow;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

public class FlowsSuspiciousOfDoS {
    
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    // Store flows related with the suspicious attack.
    private List<AlertMessageSharePriority> flowsRelatedWithThisConnection = new ArrayList<AlertMessageSharePriority>();
    // Number of flows related with this source.
    private int numberOfSuspiciousFlows=0;
    
    
    // Network source address in analysis to decide if is executing a DoS attack.
    /*
     * TODO - In the past we use this attribute to control DoS by source IP, but now not more!
     * Maybe we can remove this and others attributes related in the future...
     */
    private int networkSource = Integer.MAX_VALUE;
    
    // This status flow object will save all fields of the analyzed flow and will permit recover informations about this flow like address.
    private StatusFlow statusFlow;

    // Alert Description
    private String generalAlertDescription = "OF_DoS";
    // General priority alert of this suspicious flows.
    /*
     * During the process of this flows, we must set the priority alert of
     * AlertMessgeSharePriority to this value.
     */
    private int generalPriorityAlert = AlertMessage.NORMAL_PACKET; // first this is normal!

    public void setGeneralPriorityAlert(int generalPriorityAlert) {
        this.generalPriorityAlert = generalPriorityAlert;
    }

    /**
     * Set the first element with general priority, than due to this to be an
     * shared variable (static) this will be replaced in all this alerts
     * objects.
     * 
     * ATTENTION/CAUTION, we must change this priority for each group of source
     * network address, or this priority will be wrong, because this change the
     * priority of all message, on this group/object and in the others groups
     * and his objects. Then, all the time that a new group of alerts of one
     * specific source address is processed we can execute this method.
     */
    public void setALLAlertMessageSharePriorityObjectsWithThisGeneralPriority() {
        // if exist any element on the list. 
        if(!getFlowsRelatedWithThisConnection().isEmpty()) {
            // set the priority of all AlertMessageSharePriority objects - not just of this group!
            getFlowsRelatedWithThisConnection().get(0).setPriorityAlert(this.generalPriorityAlert);
        }
    }
    
    /**
     * Add flow in the list of related suspicious flow with this source network
     * address. And automatically: 
     *  1. convert the flow to alert message, 
     *  2. put this alert in a list of related alerts, 
     *  3. update the number of suspicious flow that math with this source address, and
     *  4. update the general alert security priority!
     */
    public void putAlertsFlowOnListOfRelatedWithThisConnection(StatusFlow statusFlow) {
        this.networkSource = statusFlow.getNetworkSource();
        AlertMessageSharePriority alertMessage = new AlertMessageSharePriority();
        alertMessage = statusFlowToAlertMessage(statusFlow);
        getFlowsRelatedWithThisConnection().add(alertMessage);
        this.updateNumberOfSuspiciousFlowsAndGeneralPriority();
    }
    
    /**
     * Update the number of suspicious flow related with this source network
     * address, and his general alert security priority. We do this looking to
     * size of flows added in flowsRelatedWithThisConnection.
     * 
     * After, we update general priority based on this number of suspicious flow
     * with few packets related with the this source network address.
     */
    private void updateNumberOfSuspiciousFlowsAndGeneralPriority() {
        this.numberOfSuspiciousFlows = getFlowsRelatedWithThisConnection().size();
        if(this.numberOfSuspiciousFlows <=20) {
            this.generalPriorityAlert = AlertMessage.NORMAL_PACKET;
        } else if(this.numberOfSuspiciousFlows > 20 && this.numberOfSuspiciousFlows <= 50 ){
            this.generalPriorityAlert=AlertMessage.ALERT_PRIORITY_LOW;
        } else if (this.numberOfSuspiciousFlows > 50 && this.numberOfSuspiciousFlows <= 100) {
            this.generalPriorityAlert=AlertMessage.ALERT_PRIORITY_MEDIUM;
        } else {
            this.generalPriorityAlert=AlertMessage.ALERT_PRIORITY_HIGH;
        }
    }
    
    /**
     * Convert this to an object Status Flow in AlertMessage (mensagemAlerta)
     * 
     * @param nCx
     * @param statusFlow
     */
    private AlertMessageSharePriority statusFlowToAlertMessage() {
        return statusFlowToAlertMessage(this.statusFlow);
    }
    
    /**
     * Convert an object Status Flow in AlertMessage (mensagemAlerta)
     * 
     * @param nCx
     * @param statusFlow
     */
    private AlertMessageSharePriority statusFlowToAlertMessage(StatusFlow statusFlow) {
        AlertMessageSharePriority alertMessage = new AlertMessageSharePriority();
        alertMessage.setNetworkSource(statusFlow.getNetworkSource());
        alertMessage.setNetworkDestination(statusFlow.getNetworkDestination());
        alertMessage.setNetworkProtocol(statusFlow.getNetworkProtocol());
        alertMessage.setTransportSource(statusFlow.getTransportSource());
        alertMessage.setTransportDestination(statusFlow.getTransportDestination());
        alertMessage.setTempo(statusFlow.getTime());
        alertMessage.setAlertDescription(this.generalAlertDescription);
        alertMessage.setPriorityAlert(this.generalPriorityAlert);
        return alertMessage;
    }
    
    /**
     * Print statistics: network address, number of suspicious flows, general alerts priority security.
     */
    public void printStatistics() {
        String alertType="none";
        if (this.generalPriorityAlert==AlertMessage.NORMAL_PACKET){
            alertType="NORMAL FLOW";
        } else if(this.generalPriorityAlert==AlertMessage.ALERT_PRIORITY_LOW){
            alertType="LOW";
        } else if (this.generalPriorityAlert==AlertMessage.ALERT_PRIORITY_MEDIUM){
            alertType="MEDIUM";
        } else if (this.generalPriorityAlert==AlertMessage.ALERT_PRIORITY_HIGH){
            alertType="HIGH";
        }
            
        log.debug("Source network Address: {}, number of suspicious flows: {}, general priority: {}.",
                this.networkSource, this.numberOfSuspiciousFlows, alertType);
    }
    
    public void printFlowsRelated() {
        this.printStatistics();
        for(AlertMessageSharePriority alert : getFlowsRelatedWithThisConnection()) {
            alert.printMsgAlert();
        }
    }

    private int getNetworkSource() {
        return networkSource;
    }

    private void setNetworkSource(int networkSource) {
        this.networkSource = networkSource;
    }

    public String getGeneralAlertDescription() {
        return generalAlertDescription;
    }

    public void setGeneralAlertDescription(String generalAlertDescription) {
        this.generalAlertDescription = generalAlertDescription;
    }

    public int getGeneralPriorityAlert() {
        return generalPriorityAlert;
    }
    
    public int getNumberOfSuspiciousFlows() {
        return numberOfSuspiciousFlows;
    }
    
    public StatusFlow getStatusFlow() {
        return statusFlow;
    }

    public void setStatusFlow(StatusFlow statusFlow) {
        this.statusFlow = statusFlow;
    }
    
    /**
     * Verify if source address have malicious flows or not!
     *  
     * @return true - have malicious flows.
     *          false - not malicious flows.
     */
    public boolean verifyIfSourceAddressHaveMaliciousFlows() {
        if(getGeneralPriorityAlert()==AlertMessage.NORMAL_PACKET) {
            return false; // not malicious!
        }
        if(getGeneralPriorityAlert()==AlertMessage.ALERT_PRIORITY_LOW) {
            return true; // malicious!
        }
        if(getGeneralPriorityAlert()==AlertMessage.ALERT_PRIORITY_MEDIUM) {
            return true; // malicious!
        }
        if(getGeneralPriorityAlert()==AlertMessage.ALERT_PRIORITY_HIGH) {
            return true; // malicious!
        }
        log.debug("ATTENTION - This source network address, have flows/alerts with a unknown priority alert!");
        return false; // not malicious!
    }

    public List<AlertMessageSharePriority> getFlowsRelatedWithThisConnection() {
        return flowsRelatedWithThisConnection;
    }

    
    // just for test don't use this
//    public void setGeneralPriorityAlert(int pri) {
//        this.generalPriorityAlert=pri;
//        setALLAlertMessageSharePriorityObjectsWithThisGeneralPriority();
//    }


}
