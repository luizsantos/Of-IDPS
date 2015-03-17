/**
 * This class is responsible to send commands to OpenFlow elements, 
 * for instance switches OpenFlow.
 * 
 * With this class is possible remove and change flows.
 * 
 *  @author Luiz Arthur Feitosa dos Santos
 *  @email luiz.arthur.feitosa.santos@gmail.com
 */

/*
 * TODO - 1. verify if the controller send one message when the controller change 
 * or delete one flow. If yes handle this message.

 * TODO - 2. Every time we have that delete or remove flows on switches, 
 * we needed to send OpenFlow messages to discover existing switches on 
 * network! Verify if is possible removing flows without use this messages, 
 * instead this use a switch passing by parameter.
 * 
 */

package net.beaconcontroller.tutorial;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.tools.ProtocolsNumbers;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionEnqueue;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ActuatorOpenFlow extends Thread implements IOFMessageListener {

    protected IBeaconProvider beaconProvider;

    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);

    /**
     * 
     * @param bP - beaconProvider
     * 
     * Start class;
     * 
     */
    public void startUp(IBeaconProvider bP) {
        //log.debug("Stating Actuator OpenFlow.");
        this.beaconProvider = bP;
        beaconProvider.addOFMessageListener(OFType.STATS_REPLY, this);        
    }
        
    
    /**
     * Stop class
     */
    public void shutDown() {
        //log.debug("Stopping OpenFlow Actuator.");
        beaconProvider.removeOFMessageListener(OFType.STATS_REPLY, this);
    }
    
    /**
     * 
     * Start actuator thread
     * 
     */
    public void run() {
        log.debug("Nothing to do in ActuatorOpenFlow Thread!");
    }

    /**
     * Handle packet received by this class.
     */
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg) throws IOException {
        log.debug("ATTENTION! Actuator received one packet... but this didn't should happen... ");
        // TODO - verify if the controller send one message when the controller change our delete one flow. If yes handle this message.
        return null;
    }

    
    /**
     * Delete/remove all flow in one switch.
     * 
     * @param sw - switch.
     */
    public void deleteAllFlowMod(IOFSwitch sw) {
        OFMatch match = new OFMatch().setWildcards(OFMatch.OFPFW_ALL);
        OFMessage fm = ((OFFlowMod) sw.getInputStream().getMessageFactory()

            .getMessage(OFType.FLOW_MOD))

            .setMatch(match)

            .setCommand(OFFlowMod.OFPFC_DELETE)

            .setOutPort(OFPort.OFPP_NONE)

            .setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));

        try {
            sw.getOutputStream().write(fm);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            log.debug("ATTENTION!!! Impossible to delete flow. (deleteAllFlowMod(IOFSwitch sw))");
            e.printStackTrace();
        }

    }

    
    /**
     * get a list with all switches on network.
     * 
     * TODO - verify if: Here this list is made sending OpenFlow messages to
     * discover switches on the network, this can produce overhead, be careful!
     * If this is true, we can use the registeredSwitches class to control
     * this list without need to send OpenFlow Message all the time! There are this
     * function implemented like method and on the code in others part of the
     * Of-IDPS!
     * 
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
        
    /**
     * Delete ALL flows in all switches on the network! 
     * 
     * If do you want delete only suspicious flows, 
     * this method can be very bad, 
     * because delete everything, 
     * suspicious or legitimate.
     * 
     * be careful...
     *      
     * */
    public void deleteAllFlowsInAllSwitches() {
        log.debug("Delete ALL flows in all switches on the network!");
        Collection<IOFSwitch> switches = new HashSet<IOFSwitch>();
        switches = getAllSwitchesOnNetwork();
        for(IOFSwitch s : switches) {
            IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
            deleteAllFlowMod(sw);
        }
    }
        
    /**
     * 
     * Delete/remove flow related with alerts messages in ALL switches in the network.
     * 
     * @param - list with alert messages (class MensagemAlerta)
     * 
     */
    public void deleteFlowsRelatedWithAlertsMessagesInAllSwitches(List<AlertMessage> listAlertMessage) {
        log.debug("Deleting flows related with security alerts on ALL switches.");
        Collection<IOFSwitch> switches = new HashSet<IOFSwitch>();
        switches = getAllSwitchesOnNetwork();
        for (AlertMessage alertMessage : listAlertMessage) {
            for (IOFSwitch s : switches) {
                IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
                OFMatch match = new OFMatch();
                if (alertMessage.getNetworkProtocol() == ProtocolsNumbers.ICMP) {
                    // Flows without ports like ICMP.
                    // TODO - but OpenFlow use ports in ICMP to handle types ICMP.
                    deleteFlowUsingIPSrcIPDstProto(alertMessage, sw, match);
                } else { 
                     /*
                     * TODO - improve this method including more specifics forms
                     * to delete flow (just sourceIP, sourceIP:port, etc!)
                     */
                    // Flows with ports!
                    deleteFlowUsingIPSrcIPDstProtoPortDst(alertMessage, sw, match);
                }
            }
        }
    }
    
    /**
     * 
     * Delete/remove flow related with AUTONOMIC rules in ALL switches in the network.
     * 
     * @param - list with alert messages (class MensagemAlerta)
     * 
     */
    public void deleteFlowsRelatedWithRulesInAllSwitches(Map<String,AlertMessage> shortMemoryAttacks) {
        log.debug("Deleting flows related with security alerts on ALL switches.");
        Collection<IOFSwitch> switches = new HashSet<IOFSwitch>();
        switches = getAllSwitchesOnNetwork();
        for (IOFSwitch s : switches) {
            IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
            for(String key : shortMemoryAttacks.keySet()) {
                AlertMessage currentRule = shortMemoryAttacks.get(key);
                //deleteFlowUsingCampsPresentsOnRule(currentRule, sw);
            }
        }
    }
    
    /**
     * 
     * Delete/remove flows only using the camps present in the security rules in ALL switches. 
     * 
     * @param currentRule - alert/rule message
     * @param sw - switch
     * @param match - OpenFlow packet
     * 
     */
    public void deleteFlowUsingCampsPresentsOnRuleInAllSwitches(AlertMessage currentRule) {
        //log.debug("Removing/deleting flow using camps presents on security rule in ALL switches.");
        //currentRule.printMsgAlert();
        // get switches on the network.
        Collection<IOFSwitch> switches = new HashSet<IOFSwitch>();
        switches = getAllSwitchesOnNetwork();

        // select which camps there are presents on the rule!
        OFMatch match = new OFMatch();
        // the variable "camps" accumulate all camps present in the rule!
        int camps = 0;
        if (currentRule.getNetworkSource() != Integer.MAX_VALUE) {
            match.setNetworkSource(currentRule.getNetworkSource());
            camps = (camps | OFMatch.OFPFW_NW_SRC_MASK);
        }
        if (currentRule.getNetworkDestination() != Integer.MAX_VALUE) {
            match.setNetworkDestination(currentRule.getNetworkDestination());
            camps = (camps | OFMatch.OFPFW_NW_DST_MASK);
        }
        if (currentRule.getNetworkProtocol() != Integer.MAX_VALUE) {
            match.setNetworkProtocol((byte) currentRule.getNetworkProtocol());
            camps = (camps | OFMatch.OFPFW_NW_PROTO);
        }
        if (currentRule.getTransportSource() != Integer.MAX_VALUE) {
            match.setTransportSource((short) currentRule.getTransportSource());
            camps = (camps | OFMatch.OFPFW_TP_SRC);
        }
        if (currentRule.getTransportDestination() != Integer.MAX_VALUE) {
            match.setTransportDestination((short) currentRule
                    .getTransportDestination());
            camps = (camps | OFMatch.OFPFW_TP_DST);
        }

        // set the camps presents on the rule.
        match.setWildcards(OFMatch.OFPFW_ALL ^ (camps));

        // send this rule to be applied in all switches of the network.
        for (IOFSwitch s : switches) {
            IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
            // delete/remove related flow!
            OFMessage fm = ((OFFlowMod) sw.getInputStream().getMessageFactory()
                    .getMessage(OFType.FLOW_MOD)).setMatch(match)
                    .setCommand(OFFlowMod.OFPFC_DELETE)
                    .setOutPort(OFPort.OFPP_NONE)
                    .setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));

            try {
                //log.debug("\tSend a delete message...");
                sw.getOutputStream().write(fm);
                //log.debug("\tDelete message sent!!!");
            } catch (IOException e) {
                // TODO Auto-generated catch block
                log.debug("ATTENTION!!! Impossible remove/delete flow.");
                e.printStackTrace();
            }
        } // end of switches for.
    }
    
    /**
     * TODO - DON'T WORK!!! Change bandwidth flows only using the camps present
     * in the security rules in ALL switches.
     * 
     * Openflow switches receive the messages but apparently don't execute the
     * change of queue and worst block the flow! Maybe is necessary to pass the
     * output port to queue method, but this class doesn't have this
     * information, this the class LearningSwitchTutorialSolition have it.
     * 
     * @param currentRule
     *            - alert/rule message
     * @param sw
     *            - switch
     * @param match
     *            - OpenFlow packet
     * 
     * 
     */
    public void changeBandwidthFlowUsingCampsPresentsOnRuleInAllSwitches(AlertMessage currentRule) {
        log.debug("Change flow using camps presents on security rule in ALL switches.");
        //currentRule.printMsgAlert();
        // get switches on the network.
        Collection<IOFSwitch> switches = new HashSet<IOFSwitch>();
        switches = getAllSwitchesOnNetwork();
        
        // select which camps there are presents on the rule!
        OFMatch match = new OFMatch();
        // the variable "camps" accumulate all camps present in the rule!
        int camps = 0;
        if (currentRule.getNetworkSource() != Integer.MAX_VALUE) {
            match.setNetworkSource(currentRule.getNetworkSource());
            camps = (camps | OFMatch.OFPFW_NW_SRC_MASK);
        }
        if (currentRule.getNetworkDestination() != Integer.MAX_VALUE) {
            match.setNetworkDestination(currentRule.getNetworkDestination());
            camps = (camps | OFMatch.OFPFW_NW_DST_MASK);
        }
        if (currentRule.getNetworkProtocol() != Integer.MAX_VALUE) {
            match.setNetworkProtocol((byte) currentRule.getNetworkProtocol());
            camps = (camps | OFMatch.OFPFW_NW_PROTO);
        }
        if (currentRule.getTransportSource() != Integer.MAX_VALUE) {
            match.setTransportSource((short) currentRule.getTransportSource());
            camps = (camps | OFMatch.OFPFW_TP_SRC);
        }
        if (currentRule.getTransportDestination() != Integer.MAX_VALUE) {
            match.setTransportDestination((short) currentRule
                    .getTransportDestination());
            camps = (camps | OFMatch.OFPFW_TP_DST);
        }

        // set the camps presents on the rule.
        match.setWildcards(OFMatch.OFPFW_ALL ^ (camps));

        // send this rule to be applied in all switches of the network.
        for (IOFSwitch s : switches) {
            IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
            
            List<OFAction> act = new ArrayList<OFAction>();
            OFActionEnqueue actionEnque = new OFActionEnqueue();
            actionEnque.setQueueId(LearningSwitchTutorialSolution.QUEUE_BANDWIDTH_LOW);
            act.add(actionEnque);
            
            short flowModLength = (short) OFFlowMod.MINIMUM_LENGTH;
            flowModLength += OFActionEnqueue.MINIMUM_LENGTH;
            
            OFMessage fm = ((OFFlowMod) sw.getInputStream().getMessageFactory()
                    .getMessage(OFType.FLOW_MOD)).setMatch(match)
                    .setCommand(OFFlowMod.OFPFC_MODIFY)
                    .setBufferId(-1)
                    .setActions(act);
            
            log.debug("\n \n Change queue a existent flow in a switch DON'T WORK! - TODO");
            
            try {
                //log.debug("\tSend a delete message...");
                sw.getOutputStream().write(fm);
                //log.debug("\tDelete message sent!!!");
            } catch (IOException e) {
                // TODO Auto-generated catch block
                log.debug("ATTENTION!!! Impossible remove/delete flow.");
                e.printStackTrace();
            }
        } // end of swithes for.
    }

    /**
     * 
     * Delete/remove all flows present in memory attack only using the camps 
     * present in the security rules in ALL switches. 
     * 
     * @param currentRule - alert/rule message
     * @param sw - switch
     * @param match - OpenFlow packet
     * 
     */
    public void deleteAllFlowUsingCampsPresentsMemoryRulesInAllSwitches(Map<String, AlertMessage> shortMemoryAttacks) {
        log.debug("Removing/deleting flow using camps presents on security rules in ALL switches.");
        // get switches on the network.
        Collection<IOFSwitch> switches = new HashSet<IOFSwitch>();
        switches = getAllSwitchesOnNetwork();
        
        // look for all rules in the short memory attacks
        for (String key : shortMemoryAttacks.keySet()) {
            AlertMessage currentRule = shortMemoryAttacks.get(key);
            // select which camps there are presents on the rule!
            OFMatch match = new OFMatch();
            // the variable "camps" accumulate all camps present in the rule!
            int camps = 0;
            if (currentRule.getNetworkSource() != Integer.MAX_VALUE) {
                match.setNetworkSource(currentRule.getNetworkSource());
                camps = (camps | OFMatch.OFPFW_NW_SRC_MASK);
            }
            if (currentRule.getNetworkDestination() != Integer.MAX_VALUE) {
                match.setNetworkDestination(currentRule.getNetworkDestination());
                camps = (camps | OFMatch.OFPFW_NW_DST_MASK);
            }
            if (currentRule.getNetworkProtocol() != Integer.MAX_VALUE) {
                match.setNetworkProtocol((byte) currentRule
                        .getNetworkProtocol());
                camps = (camps | OFMatch.OFPFW_NW_PROTO);
            }
            if (currentRule.getTransportSource() != Integer.MAX_VALUE) {
                match.setTransportSource((short) currentRule
                        .getTransportSource());
                camps = (camps | OFMatch.OFPFW_TP_SRC);
            }
            if (currentRule.getTransportDestination() != Integer.MAX_VALUE) {
                match.setTransportDestination((short) currentRule
                        .getTransportDestination());
                camps = (camps | OFMatch.OFPFW_TP_DST);
            }

            // set the camps presents on the rule.
            match.setWildcards(OFMatch.OFPFW_ALL ^ (camps));
            
            // send this rule to be applied in all switches of the network.
            for (IOFSwitch s : switches) {
                IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
                // delete/remove related flow!
                    OFMessage fm = ((OFFlowMod) sw
                        .getInputStream()
                        .getMessageFactory()
                        .getMessage(OFType.FLOW_MOD))
                        .setMatch(match)
                        .setCommand(OFFlowMod.OFPFC_DELETE)
                        .setOutPort(OFPort.OFPP_NONE)
                        .setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));

                try {
                    sw.getOutputStream().write(fm);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    log.debug("ATTENTION!!! Impossible remove/delete flow.");
                    e.printStackTrace();
                }
            } // end of switches for.
        } // end current rules for.
    }
    

    /**
     * 
     * Delete/remove flows only using source and destination network address,
     * and network protocol. This can be used to remove ICMP flows that hasn't
     * ports. 
     * 
     * * ATTENTION, beacon OpenFlow presents number related with port to
     * ICMP, probably this is the ICMP code or type. 
     * 
     * TODO - Maybe is interesting handle this.
     * 
     * @param msg - alert/rule message
     * @param sw - switch
     * @param match - OpenFlow packet
     * 
     * 
     */
    private void deleteFlowUsingIPSrcIPDstProto(AlertMessage msg, IOFSwitch sw,
            OFMatch match) {
        log.debug("Removing/deleting flow using IPsrc, IPDst and protocol");
        match.setNetworkSource(msg.getNetworkSource());
        match.setNetworkDestination(msg.getNetworkDestination());
        match.setNetworkProtocol((byte) msg.getNetworkProtocol());
        match.setWildcards(OFMatch.OFPFW_ALL
                ^ (OFMatch.OFPFW_NW_SRC_MASK | OFMatch.OFPFW_NW_DST_MASK | OFMatch.OFPFW_NW_PROTO));

        OFMessage fm = ((OFFlowMod) sw.getInputStream()
                .getMessageFactory()

                .getMessage(OFType.FLOW_MOD))

        .setMatch(match)

        .setCommand(OFFlowMod.OFPFC_DELETE)

        .setOutPort(OFPort.OFPP_NONE)

        .setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));

        try {
            sw.getOutputStream().write(fm);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            log.debug("ATTENTION!!! Impossible remove/delete flow.");
            e.printStackTrace();
        }
    }
    
    /**
     * 
     * Delete/remove flows only using source and destination network address,
     * network protocol and destination port - don't use source port!
     * 
     *  We used this method because, many times the source port is
     *  unknown in the client side, then we don't use the source port
     *  to remove the flow!
     * 
     * @param msg - alert message
     * @param sw - switch
     * @param match - OpenFlow packet
     * 
     *            TODO - Make a method treats source port or all camps.
     * 
     * 
     */
    private void deleteFlowUsingIPSrcIPDstProtoPortDst(AlertMessage msg, IOFSwitch sw,
            OFMatch match) {
        log.debug("Removing/deleting flow using IPsrc, IPDst, protocol and dstPort");
        // match.setNetworkProtocol((byte) 0x01);
        match.setNetworkSource(msg.getNetworkSource());
        match.setNetworkDestination(msg.getNetworkDestination());
        match.setNetworkProtocol((byte) msg.getNetworkProtocol());
        //match.setTransportSource((short) msg.getTransportSource());
        match.setTransportDestination((short) msg.getTransportDestination());
        match.setWildcards(OFMatch.OFPFW_ALL
                ^ (OFMatch.OFPFW_NW_SRC_MASK | OFMatch.OFPFW_NW_DST_MASK | OFMatch.OFPFW_NW_PROTO |
                        OFMatch.OFPFW_TP_DST));

        OFMessage fm = ((OFFlowMod) sw.getInputStream()
                .getMessageFactory()

                .getMessage(OFType.FLOW_MOD))

        .setMatch(match)

        .setCommand(OFFlowMod.OFPFC_DELETE)

        .setOutPort(OFPort.OFPP_NONE)

        .setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));

        try {
            sw.getOutputStream().write(fm);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            log.debug("ATTENTION!!! Impossible remove/delete flow.");
            e.printStackTrace();
        }
    }


}
