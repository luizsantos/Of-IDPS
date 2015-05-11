/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */

/**
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 * This class starts all processes to OF-IDPS.
 * 
 * This class receive packets from switches to decide if the packets will be
 * forwarded to the network or if this packet represent a threat and must be
 * mitigated.
 * 
 * It is based on tutorial class used to teach how to build a simple layer 2
 * learning switch. (@author David Erickson (daviderickson@cs.stanford.edu) -
 * 10/14/12)
 * 
 */
package net.beaconcontroller.tutorial;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.OfIDPS.memoryAttacks.MemoryAttackRuleMatch;
import net.OfIDPS.memoryAttacks.MemorysAttacks;
import net.beaconcontroller.IPS.AlertMessage;
import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.core.IOFSwitchListener;
import net.beaconcontroller.packet.Ethernet;
import net.beaconcontroller.packet.IPv4;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionEnqueue;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class LearningSwitchTutorialSolution implements IOFMessageListener,
        IOFSwitchListener {
    
    /*
     * To variables disable* below, use 1 to disable or any other value to enable, like 0 (zero).
     */
    /*
     * Use to enable or disable ALL Of-IDPS architecture.
     */
    protected static int disableOfIDPS=0;
    /*
     * This can disable the ability of Of-IDPF collect Openflows statistics 
     * messages from network elements, like switches.
     * If this is is equal to 1 (enable), this will too affect disable the
     * disableOfIDPS_UseOfAlerts because we won't have OpenFlow data to do
     * the analysis. 
     */
    public static int disableOfIDPS_UseOfgetStatisticsFromNetwork=0;
    /*
     * Enable or disable the analysis of security threats based on OpenFlow
     * statistics, this depend that the
     * disableOfIDPS_UseOfgetStatisticsFromNetwork variable is enabled
     * (different of 1).
     * 
     * If just this variable is disabled and the
     * disableOfIDPS_UseOfgetStatisticsFromNetwork variable is enable, then, the
     * Of-IDPS will just collect Openflow statistics messages but won't use this
     * for reactions.
     * 
     * This is used, here and in the MemoryAttacks class.
     */
    public static int disableOfIDPS_UseOfAlerts=0;
    /*
     *  Enable or disable the use of IDS message on the Of-IDPS
     *  
     *  This is used in the MemoryAttacks class.
     *  
     */
    public static int disableOfIDPS_UseIDSAlerts=1;
    
    /*
     * Used to send and receive OpenFlow statistics messages, like flows
     * installed in OpenFlow switches.
     */
    SensorOpenFlow sensorOF = new SensorOpenFlow();
    
    /*
     * Used to analyze OpenFlow message to decide if network have troubles, for
     * example we can use this to identify if network is under attack.
     */
    AnalysisFlow analysisFlow = new AnalysisFlow();
    
    /*
     * Memory attacks is used to store rules that can be applied in packets analyzed by this
     * OpenFlow controller, this will decide if this packets will has flows
     * normally installed, installed with bandwidth reduction, or blocked.
     *
     * SensoriaMemoryAttacks - Store rules that represent attacks that are occurring now, this rules
     * will correspond directly with the socket network from the security alerts
     * (IDS, OpenFlow, etc). TODO - We have that implement SensorialMemoryAttacks yet.
     * 
     * 
     */
    Map<String, AlertMessage> sensorialMemoryAttacks = new HashMap<String, AlertMessage>();
    /*
     * shortMemoryAttacks used to store security rules that are created by the
     * MemorysAttacks class, using recent security alerts from IDS and OpenFlow
     * statistics messages. This rules are created using the itemsets algorithm
     * that make this autonomically.
     */
    Map<String, AlertMessage> shortMemoryAttacks = new HashMap<String, AlertMessage>();
    /*
     * longMemoryAttacks used to store security rules that are created by the
     * MemorysAttacks class, using recent and old security alerts from IDS and
     * OpenFlow statistics messages. This rules are created using the itemsets
     * algorithm that make this autonomically. TODO - this needed to be
     * implemented yet.
     */
    Map<String, AlertMessage> longMemoryAttacks = new HashMap<String, AlertMessage>();
    
    /*
     * Starts the MemorysAttacks object that will populate the attacks memory
     * with security rules, that will be used to this class. This rules are
     * returned indirectly, like pointer.
     */
    protected MemorysAttacks memoryAttacks = new MemorysAttacks(
            shortMemoryAttacks, longMemoryAttacks, sensorialMemoryAttacks);
    
    private static int countNormalPackets=0;
    private static int countAlertPriorityLow=0;
    private static int countAlertPriorityMediun=0;
    private static int countAlertPriorityHigh=0;
    private static int countAlertPriorityUnknow=0;
    //All packets handle in switch forward IPS method, not all handle by receive method! 
    private static int countAllArrivedPackets=0;
    private static int countPacketsToOfController=0;
    private static int countSentLikeHub=0;
    
    // IP of OpenFlow controller
    //private static int controllerOfIP = IPv4.toIPv4Address("192.168.2.111");
    private static Set<Integer> allowIPs = new HashSet<Integer>();
    static {
        allowIPs.add(IPv4.toIPv4Address("192.168.2.111")); 	// OpenFlow controller;
    	allowIPs.add(IPv4.toIPv4Address("192.168.2.112")); 	// Xen Controller - on eth1;
    	allowIPs.add(IPv4.toIPv4Address("172.16.2.130")); 	// Xen Controller - on eth0;
    	allowIPs.add(IPv4.toIPv4Address("192.168.2.133")); 	// IDS;
    }

    // used to print messages!
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    // Used to send/receive OpenFlow messages.
    protected IBeaconProvider beaconProvider;
    
    /*
     * Used to store switch known ports, discovered during the normal switch
     * processing. For instance, host 1 is connected on the port 3 of switch 2.
     */
    protected Map<IOFSwitch, Map<Long, Short>> macTables = new HashMap<IOFSwitch, Map<Long, Short>>();
    
    // TODO - verify commentary in the class:
    //private RegisteredSwitches registredSwitches = new RegisteredSwitches(beaconProvider);
    
    /*
     * Constants that represent respectively, HIGH bandwidth reduction, MEDIUM
     * bandwidth reduction, LOW bandwidth reduction, and BLOCK network packets.
     */
    public final static int QUEUE_BANDWIDTH_HIGH = 0;
    public final static int QUEUE_BANDWIDTH_MEDIUM = 1;
    public final static int QUEUE_BANDWIDTH_LOW = 2;
    public final static int BLOCK_PACKET = 0;
    

    /**
     * Processes Openflow messages that arriving on the controller.
     * 
     * @param - sw, switch that sent this message.
     * @param - OpenFlow message that was sent.
     * 
     *        Obs. This method is very important, because is automatically
     *        called when one OpenFlow packet arrive on the controller, and this
     *        will start the Of-IDPS processing to this arrived packet, this
     *        processing can be forward this packet normally installing a simple
     *        flow on the switch, installing this packet with bandwidth
     *        reduction, or block this and all subsequent packets, this will
     *        depend of rules installed on the attacks memory.
     */
    public Command receive(IOFSwitch sw, OFMessage msg) throws IOException {
        initMACTable(sw);
                
        if (msg instanceof OFPacketIn) {
            OFPacketIn pi = (OFPacketIn) msg;
            
            // Send all packets like a hub!
            // forwardAsHub(sw, pi);
            
            // Send packets using a switch method and with the Of-IDPS architecture.
            forwardAsLearningSwitchWithIPS(sw, pi);
        }
        return Command.CONTINUE;
    }


    /**
     * EXAMPLE CODE: Floods the packet out all switch ports except the port it
     * came in on.
     * 
     * @param sw
     *            the OpenFlow switch object
     * @param pi
     *            the OpenFlow Packet In object
     * @throws IOException
     */
    public void forwardAsHub(IOFSwitch sw, OFPacketIn pi) throws IOException {
        // Create the OFPacketOut OpenFlow object
        OFPacketOut po = new OFPacketOut();

        // Create an output action to flood the packet, put it in the
        // OFPacketOut
        OFAction action = new OFActionOutput(OFPort.OFPP_FLOOD.getValue());
        po.setActions(Collections.singletonList(action));

        // Set the port the packet originally arrived on
        po.setInPort(pi.getInPort());

        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), (short) 0);
        // print packet
        /*
         * log.info("PortIn {}:", pi.getInPort());
         * log.info("L2  type {}, {}->{}",match.getDataLayerType(),
         * HexString.toHexString
         * (match.getDataLayerSource()),HexString.toHexString
         * (match.getDataLayerDestination()));
         * log.info("L3 proto {}, {}->{}",match
         * .getNetworkProtocol(),IPv4.fromIPv4Address
         * (match.getNetworkSource()),IPv4
         * .fromIPv4Address(match.getNetworkDestination()));
         */
        // Reference the packet buffered at the switch by id
        po.setBufferId(pi.getBufferId());
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            /**
             * The packet was NOT buffered at the switch, therefore we must copy
             * the packet's data from the OFPacketIn to our new OFPacketOut
             * message.
             */
            po.setPacketData(pi.getPacketData());
        }
        // Send the OFPacketOut to the switch
        sw.getOutputStream().write(po);
    }

    /**
     * 
     * Use learning switch method plus the Of-IDPS security rules!
     * 
     * @param sw
     *            - switch.
     * @param pi
     *            - packet in (packet that arrived on the controller).
     * @throws IOException. Forward
     *             the arrived packets like, here in order: 1) Verify if the
     *             destination port to this packet is known. If this port is
     *             unknown send this packet for all ports of switch using
     *             forwardAsHub method.
     * 
     *             2) But, if the destination port is already known the
     *             controller will submit to the rules on the memory
     *             (sensorial,short, long) attacks, in this process we will
     *             have: 2.1) if this packet don't combine with NO rules a new
     *             flow will be installed on the switch, and this packet and all
     *             subsequent will be sent normally. 2.2) if this packet combine
     *             with a low priority security rule, a new flow with soft
     *             bandwidth will be installed on the switch, and this packet
     *             and all subsequent will be sent with this bandwidth
     *             reduction. 2.3) if this packet combine with a medium priority
     *             security rule, a new flow with severe bandwidth will be
     *             installed on the switch, and this packet and all subsequent
     *             will be sent with this bandwidth reduction. 2.4) if this
     *             packet combine with a high priority security rule, no flows
     *             are installed to this packet and this will be blocked.
     * 
     *             TODO - related to 2.4, verify if is possible installing a flow that
     *             blocked a packet and subsequents on the switch, thus the
     *             subsequents won't be constantly sent to the controller. But
     *             the first task is verify if this problem really exists!
     */

    public void forwardAsLearningSwitchWithIPS(IOFSwitch sw, OFPacketIn pi)
            throws IOException {

        Map<Long, Short> macTable = macTables.get(sw);

        // Build the Match
        OFMatch match = OFMatch.load(pi.getPacketData(), pi.getInPort());

        // Learn the port to reach the packet's source MAC
        macTable.put(Ethernet.toLong(match.getDataLayerSource()),
                pi.getInPort());

        // Retrieve the port previously learned for the packet's dest MAC
        Short outPort = macTable.get(Ethernet.toLong(match
                .getDataLayerDestination()));

        /*
         * TODO - maybe is better create the two flows for the network
         * connection at same time, for now we create first host1->host2 and
         * after in another moment host2->host1, but maybe we can create at same
         * time this two flows host1->host2 and host2->host1.
         */

        // Firstly all packets are normal, but after the security rules on memory attacks can change this.
        int acao = AlertMessage.NORMAL_PACKET;
        
        /*
         * if port is unknown sent like a hub for all ports of the switch! 
         * But, if the port is know (different of null) processes in the
         * Of-IDPS!
         */
        if (outPort != null) {
        	// If packet if from or to OpenFlow controller the just sent this!
        	//if (controllerOfIP==match.getNetworkSource() || controllerOfIP==match.getNetworkDestination()) {
        	if(allowIPs.contains(match.getNetworkSource()) || allowIPs.contains(match.getNetworkDestination())) {
                    sendPacketNormally(sw, pi, match, outPort);
                    log.debug(">>>>>>   ATTENTION - Packets from {}->{} " +
                    		"combines with allowed IPs, thus a flow was added without be submitted to Of-IDPS security rules. " +
                    		"(ex. OpenFlow controller, IDS, XenServer, etc...)!", 
                    		IPv4.fromIPv4Address(match.getNetworkSource()),IPv4.fromIPv4Address(match.getNetworkDestination()));
                    countPacketsToOfController++;
            } else {
        		
        	
            
//            log.debug("Packet being analyzed:");
//            printPacketMatch(match);
                        
            if (disableOfIDPS != 1) {
                
                // memoryAttacks.printMemoryAttacks(sensorialMemoryAttacks);
                // memoryAttacks.printMemoryAttacks(shortMemoryAttacks);
                memoryAttacks.printMemoryAttacks(longMemoryAttacks);
                
                MemoryAttackRuleMatch memoryAttackRuleMatch =  new MemoryAttackRuleMatch();
                
                // Verify if this packet match with one rule of sensorial memory!
                memoryAttackRuleMatch = analyzePacketInTheMemoryAttack(match, sensorialMemoryAttacks);
                if(memoryAttackRuleMatch.isMatch()) {
                    // If there is a rule, update the action!
                    acao = memoryAttackRuleMatch.getAction();
                    log.debug("Packet match with a sensorial memory rule!");
                } else {
                   
                    // Verify if this packet match with one rule of short memory!
                    memoryAttackRuleMatch = analyzePacketInTheMemoryAttack(match, shortMemoryAttacks);
                    if(memoryAttackRuleMatch.isMatch()) {
                        // If there is a rule, update the action!
                        acao = memoryAttackRuleMatch.getAction();
                        log.debug("Packet match with a short memory rule!");
                    
                    } else {
                    
                        // Verify if this packet match with one rule of long memory!
                        memoryAttackRuleMatch = analyzePacketInTheMemoryAttack(match, longMemoryAttacks);
                        if(memoryAttackRuleMatch.isMatch()) {
                         // If there is a rule, update the action!
                            acao = memoryAttackRuleMatch.getAction();
                            log.debug("Packet match with a long memory rule!");
                        } else {
                            log.debug("Packet no match with any memory rule!");
                        }
                    }
                }

                if(memoryAttackRuleMatch.isMatch()) {
                    acao = handlePacketsWithoutPriority(acao);
                }

            // Use this else case the architecture of Of-IDPS is disable
            } else {
                //log.debug("\t!!!!!!!! Of-IDPS DISABLE !!!!!!!  for change this setup to 0 (zero) the variable disableOfIDPS on LearningSwithTutorialSolution class...");
                acao = AlertMessage.NORMAL_PACKET;
            }
            
         // TEST - Just for TEST set to bandwitdth MEDIUM all with priority different that NORMAL
//            if(acao!=AlertMessage.NORMAL_PACKET) {
//                acao=AlertMessage.ALERT_PRIORITY_MEDIUM;
//                log.debug("\t\t!!!!!!CAUTION, all alerts there are BANDWITHD MEDIUM in this test!!");
//            }
            
            countAllArrivedPackets++;
            
            // TODO - TEST
//            if(countAllArrivedPackets<500) {
//                acao=AlertMessage.NORMAL_PACKET;
//            } else if (countAllArrivedPackets<1000) {
//                acao=AlertMessage.ALERT_PRIORITY_LOW;
//            } else if (countAllArrivedPackets<1500) {
//                acao=AlertMessage.ALERT_PRIORITY_MEDIUM;
//            } else {
//                acao=AlertMessage.ALERT_PRIORITY_HIGH;
//            }
            // TODO - TEST END.
           
            /*
             * Now based on the alert priority or in his absence decide how
             * forward this packet and subsequent.
             */
            switch (acao) {
                case AlertMessage.NORMAL_PACKET:
                    log.debug("!$!$!$!NORMAL PACKET, forward without alerts!");
                    sendPacketNormally(sw, pi, match, outPort);
                    countNormalPackets++;
                    // enviaPacoteQueue(sw, QUEUE_LARGURA_BANDA_ALTA, match,
                    // outPort, pi);
                    break;
                case AlertMessage.ALERT_PRIORITY_LOW:
                    //log.debug("!-!-!-! LOW security priority, forward to SOFT decrease bandwidth!");
                    log.debug("LOW");
                    sendPacketUsingBandwidthQueue(sw, QUEUE_BANDWIDTH_MEDIUM, match,
                            outPort, pi);
                    countAlertPriorityLow++;
                    break;
                case AlertMessage.ALERT_PRIORITY_MEDIUM:
                    //log.debug("!+!+!+! MEDIUM security priority, forward to SEVERE decrease bandwidth!");
                    log.debug("MEDIUM");
                    sendPacketUsingBandwidthQueue(sw, QUEUE_BANDWIDTH_LOW, match,
                            outPort, pi);
                    countAlertPriorityMediun++;
                    break;
                case AlertMessage.ALERT_PRIORITY_HIGH:
                    log.debug("HIGH");
                    //log.debug("!*!*!*! HIGH security priority, BLOCK this packet and all subsequent.");
                    countAlertPriorityHigh++;
                    break;
                default:
                    log.debug("********ATTENTION - Packet with security PRIORITY UNKNOWN, forward normally!!!*******");
                    sendPacketNormally(sw, pi, match, outPort);
                    countAlertPriorityUnknow++;
            }
            
//            log.debug("Controller arrived: {} normal, {} low, {} medium, {} high, {} unknow, total: {}",
//                    countNormalPackets, countAlertPriorityLow, countAlertPriorityMediun, countAlertPriorityHigh, countAlertPriorityUnknow, countAllArrivedPackets);
        	}
        } else {
            // Destination port unknown, flood packet to all ports
            forwardAsHub(sw, pi);
            countSentLikeHub++;
        }
        
//        JSONObject ofIDPSPacketsStatus = new JSONObject();
//        ofIDPSPacketsStatus.put("normalPkts", countNormalPackets);
//        ofIDPSPacketsStatus.put("lowPkts", countAlertPriorityLow);
//        ofIDPSPacketsStatus.put("mediumPkts", countAlertPriorityMediun);
//        ofIDPSPacketsStatus.put("highPkts", countAlertPriorityHigh);
//        ofIDPSPacketsStatus.put("highUnknowPkts", countAlertPriorityUnknow);
//        ofIDPSPacketsStatus.put("allPkts", countAllArrivedPackets);
//        ofIDPSPacketsStatus.put("hugPkts", countSentLikeHub);
        
        
    }


    /**
     * 
     * Analyzes if a there is match  with an arriving packet and 
     * a rule on a specific memory (sensorial, short, and long).
     * If the arriving packet combine with an already existing rule, 
     * this method also increase the life of this rule.
     * 
     * @param match - packet arriving on the controller.
     * @param memoryAtacks - memory to be analyzed.
     * @return - A MemoryAttackRule object that inform if 
     *  there is match and the level of security priority to be applied as action to the packet. 
     */
    private MemoryAttackRuleMatch analyzePacketInTheMemoryAttack(OFMatch match, Map<String, AlertMessage> memoryAtacks) {
        // To store/return the result!
        MemoryAttackRuleMatch memoryAttackRuleMatch =  new MemoryAttackRuleMatch();
        /*
         * Get network socket from the packet that will be analyzed by
         * Of-IDPS.
         */
        String analysedPacketKeySocketNetwork = getKeyNetworkSocketFromAnalysedPacket(match);
        /*
         * Search if the analyzed packet have one specific rule on the
         * memory of attacks. That's, is this packet have a perfect
         * rule, that match with all camps from packet.
         */
        AlertMessage alertMsg = null;
        
        
        alertMsg = memoryAtacks.get(analysedPacketKeySocketNetwork);

        if (alertMsg != null) {
            /*
             * if the analyzed packet perfectly matches with an alert
             * entry, apply the security priority associated with this
             * alert!
             * 
             * Maybe the alert don't have an priority associated, due to
             * the logic of itemsets algorithm and, then this is treated
             * to the method handlePacketsWithoutPriority()
             */
            //log.debug("Packet perfectly matches with alert: ");
            memoryAttackRuleMatch.setMatch(true);
            memoryAttackRuleMatch.setAction(alertMsg.getPriorityAlert());
        } else {
            /*
             * If the analyzed packet don't matches perfectly with all
             * camps, then will be analyzed entry by entry, searching an
             * entry what better match with the analyzed packet.
             * 
             * The itemsets algorithm, produces more generic rules, this
             * is, rules with less items to be analyzed. Then here, we
             * will compare if exists one entry that better combine with
             * the packet using only some camps. Attention! For this,
             * camps with the value Integer.MAX_VALUE combine with any
             * value, in other words, is a wildcard * (any).
             */
            // Zero don't combine - different of zero combine
            int combine = 0;
            // Number of camps from rule that combine with the analyzed
            // packet
            int numberCampsThatCombinePerfectly = 0;
            // Search for all rules in short memory
            
            // test
            // This will save the key rule that better combine with the packet. We use this to keep alive this rule.
            String matchKey=null;
            for (String key : memoryAtacks.keySet()) {
                int auxCombine = 0;
                int auxNumberCampsThatCombinePerfectly = 0;
                AlertMessage currentRule = memoryAtacks.get(key);

                // Analyze NetworkSource
                if (currentRule.getNetworkSource() == match.getNetworkSource()) {
                    // Both camps match perfectly
                    auxNumberCampsThatCombinePerfectly++;
                } else if (currentRule.getNetworkSource() != Integer.MAX_VALUE) {
                    // If this is true, stop the analysis of rule if one
                    // camp doesn't match.
                    continue;
                    // But, if this is false, then doesn't match
                    // perfectly, but the same camp on the rule is a
                    // wildcard (Integer.MAX_VALUE), that represents any
                    // (*), that forces the matches.
                }

                // Analyze NetworkDestination
                if (currentRule.getNetworkDestination() == match.getNetworkDestination()) {
                    // Both camps match perfectly
                    auxNumberCampsThatCombinePerfectly++;
                } else if (currentRule.getNetworkDestination() != Integer.MAX_VALUE) {
                    // If this is true, stop the analysis of rule if one
                    // camp doesn't match.
                    continue;
                    // But, if this is false, then doesn't match
                    // perfectly, but the same camp on the rule is a
                    // wildcard (Integer.MAX_VALUE), that represents any
                    // (*), that forces the matches.
                }

                // Analyze NetworkProtocol
                if (currentRule.getNetworkProtocol() == match
                        .getNetworkProtocol()) {
                    // Both camps match perfectly
                    auxNumberCampsThatCombinePerfectly++;
                } else if (currentRule.getNetworkProtocol() != Integer.MAX_VALUE) {
                    // If this is true, stop the analysis of rule if one
                    // camp doesn't match.
                    continue;
                    // But, if this is false, then doesn't match
                    // perfectly, but the same camp on the rule is a
                    // wildcard (Integer.MAX_VALUE), that represents any
                    // (*), that forces the matches.
                }

                // Analyze TransportSource
                if (currentRule.getTransportSource() == match
                        .getTransportSource()) {
                    // Both camps match perfectly
                    auxNumberCampsThatCombinePerfectly++;
                } else if (currentRule.getTransportSource() != Integer.MAX_VALUE) {
                    // If this is true, stop the analysis of rule if one
                    // camp doesn't match.
                    continue;
                    // But, if this is false, then doesn't match
                    // perfectly, but the same camp on the rule is a
                    // wildcard (Integer.MAX_VALUE), that represents any
                    // (*), that forces the matches.
                }

                // Analyse TransportDestination
                if (currentRule.getTransportDestination() == match
                        .getTransportDestination()) {
                    // Both camps match perfectly
                    auxNumberCampsThatCombinePerfectly++;
                } else if (currentRule.getTransportDestination() != Integer.MAX_VALUE) {
                    // If this is true, stop the analysis of rule if one
                    // camp doesn't match.
                    continue;
                    // But, if this is false, then doesn't match
                    // perfectly, but the same camp on the rule is a
                    // wildcard (Integer.MAX_VALUE), that represents any
                    // (*), that forces the matches.
                }

                /*
                 * If the rule processing, has reached at this point, it
                 * means that this rule match with the analysed packet.
                 */
                if (auxNumberCampsThatCombinePerfectly > numberCampsThatCombinePerfectly) {
                    // log.debug("\tCurrent rule math with the packet, the oldest was {} the new is {}",
                    // numberCampsThatCombinePerfectly,
                    // auxNumberCampsThatCombinePerfectly);
                    numberCampsThatCombinePerfectly = auxNumberCampsThatCombinePerfectly;
                    alertMsg = currentRule;

                    /*
                     * Attention! Maybe the alert don't have an priority
                     * associated, due to the logic of itemsets
                     * algorithm and, then this is treated to the method
                     * handlePacketsWithoutPriority()
                     */
                    //acao = currentRule.getPriorityAlert();
                    memoryAttackRuleMatch.setMatch(true);
                    memoryAttackRuleMatch.setAction(alertMsg.getPriorityAlert());
                    // log.debug("\t>>> The priority was set by an AUTONOMIC rule, the value of priority was: "+ acao);
                    matchKey = key;
                }
            }
            
            /*
             * Update the counter of packets that combine with this rule! 
             * This will revive this rules and help to show that this 
             * rules still in use!
             * 
             * TODO - Maybe we should store the total of packets that combine 
             * with this rule during all rule life... and make the average of 
             * packets during this time! this can be useful to decide if this 
             * packets are result of attacks or not! Mainly to detect DoS... 
             * 
             */
            //TESTE
            if (matchKey!=null) {
                AlertMessage ruleThatCombine = memoryAtacks.get(matchKey);
                ruleThatCombine.increasePacketsMatchInOfControllerPerHop();
                /*
                 * if we use this is necessary to uncomment the code 
                 * entry.getValue().verifyAndUpdatePacketsMatchInOfController();
                 * on MemorysAttacks class.
                 */
                ruleThatCombine.increasePacketsMatchInOfControllerPerHop();
                /*
                 * TODO - not is more easy just increase the time live of this rule?
                 */
//                        ruleThatCombine.increaseLife();
            }
        }

        //printIfPacketMathWithSecurityRule(alertMsg);
        return memoryAttackRuleMatch;
    }


    /**
     * Print if packet in math with an extent rule.
     * 
     * @param alertMsg - alert message
     */
    private void printIfPacketMathWithSecurityRule(AlertMessage alertMsg) {
        if (alertMsg == null) {
            log.debug("\tThis packet din't match with the list of alert rules");
        } else {
            log.debug("\tThis packet match with alert rule:");
            alertMsg.printMsgAlert();
        }
    }

    /**
     * 
     * Remember, the order of analysedPacketKeySocketNetwork camps MUST be the
     * same of method getKeyFromNetworkSocket in AlertsMessage (MensagemAlerta)
     * class
     * 
     * @param match - network packet, that will be extracted the socket key 
     * @return - One string that represent the network socket.
     */
    private String getKeyNetworkSocketFromAnalysedPacket(OFMatch match) {
        String analysedPacketKeySocketNetwork = 
                Integer.toString(match.getNetworkSource())
                + Integer.toString(match.getNetworkDestination())
                + Integer.toString(match.getNetworkProtocol())
                + Integer.toString(match.getTransportSource())
                + Integer.toString(match.getTransportDestination());
        return analysedPacketKeySocketNetwork;
    }

    /**
     * 
     * Select a security priority if the alert rule generated by itemset
     * algorithm don't have an priority associated. Maybe the alert don't have
     * an priority associated due to the logic of itemsets algorithm.
     * 
     * @param acao
     *            - action analyzed - if action (acao) have this value in
     *            Integer.MAX_VALUE, means that this packet matches with a rule
     *            that didn't have an associated priority.
     * @return acao - action to be applied to the packet flow.
     */
    private int handlePacketsWithoutPriority(int acao) {
        if(acao==Integer.MAX_VALUE) {
            /**
             * TODO - Alerts without priority must be configured with
             * dynamic priorities, based on the type/description from
             * attack.
             * 
             * For now, this alerts will be set with a static value.
             * 
             */
            acao=AlertMessage.ALERT_PRIORITY_HIGH;
            log.debug("This alert don't have an related priority. Setting this with a high priority {}/{}.", "HIGH",acao);
        }
        //log.debug("-----> Flow from this packet was set with priority: {}", acao);
        return acao;
    }

    /**
     * Print packet that being analyzed by controller.
     * 
     * @param match
     */
    private void printPacketMatch(OFMatch match) {
        log.debug(match.getNetworkSource()+":"+match.getTransportSource()+"->"+
                match.getNetworkDestination()+":"+match.getTransportDestination()+" ("+
                match.getNetworkProtocol()+")");
    }

    /**
     * 
     * Delete/remove flows using just IP source and destination address.
     * 
     * @param sw - Switch.
     * @param match - Network packet.
     * 
     * TODO - Verify if this method can be removed to ActuatorOpenFlow class.
     *  
     */
    private void deleteFlowUsingIPSrcIPDst(IOFSwitch sw, OFMatch match) {
        // match.setNetworkSource(msg.getNetworkSource());
        // match.setNetworkDestination(msg.getNetworkDestination());
        // match.setNetworkProtocol((byte) msg.getNetworkProtocol());
        match.setWildcards(OFMatch.OFPFW_ALL
                ^ (OFMatch.OFPFW_NW_SRC_MASK | OFMatch.OFPFW_NW_DST_MASK));

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
            log.debug("Impossible to delete flow");
            e.printStackTrace();
        }
    }

    /**
     * Delete ALL flows in one switch!
     * 
     * @param sw - Switch.
     * 
     */
    private void deleteAllFlowMod(IOFSwitch sw) {
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
            log.debug("Impossible to delete flow");
            e.printStackTrace();
        }

    }

    /**
     * Send packet normally to the network, without restrictions!
     * 
     * @param sw - Switch.
     * @param pi - Packet network in.
     * @param match - Packet been analyzed.
     * @param outPort - Known output switch port.
     * @throws IOException
     */
    private void sendPacketNormally(IOFSwitch sw, OFPacketIn pi, OFMatch match,
            Short outPort) throws IOException {
        // Destination port known, push down a flow
        OFFlowMod fm = new OFFlowMod();
        fm.setBufferId(pi.getBufferId());
        // Use the Flow ADD command
        fm.setCommand(OFFlowMod.OFPFC_ADD);
        // Time out the flow after 5 seconds if inactivity
        fm.setIdleTimeout((short) 5);
        // Match the packet using the match created above
        fm.setMatch(match);
        // Send matching packets to outPort
        OFAction action = new OFActionOutput(outPort);
        fm.setActions(Collections.singletonList((OFAction) action));
        // Send this OFFlowMod to the switch
        sw.getOutputStream().write(fm);

        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            /**
             * EXTRA CREDIT: This is a corner case, the packet was not buffered
             * at the switch so it must be sent as an OFPacketOut after sending
             * the OFFlowMod
             */
            OFPacketOut po = new OFPacketOut();
            action = new OFActionOutput(outPort);
            po.setActions(Collections.singletonList(action));
            po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
            po.setInPort(pi.getInPort());
            po.setPacketData(pi.getPacketData());
            sw.getOutputStream().write(po);
        }
    }

    /**
     * 
     * Send packet using one bandwidth reduction queue to the network.
     * 
     * @param sw - Switch.
     * @param queueNumber - Queue file number - type of bandwidth reduction (soft, severe).
     * @param match - Analyzed packet network.
     * @param outPort - Known output switch port.
     * @throws IOException
     */
    private void sendPacketUsingBandwidthQueue(IOFSwitch sw, int queueNumber, OFMatch match,
            Short outPort, OFPacketIn pi) throws IOException {
        List<OFAction> act = new ArrayList<OFAction>();
        short flowModLength = (short) OFFlowMod.MINIMUM_LENGTH;

        OFActionEnqueue actionEnque = new OFActionEnqueue();
        actionEnque.setPort(outPort);
        actionEnque.setQueueId(queueNumber); // number of queue that will be used.
        flowModLength += OFActionEnqueue.MINIMUM_LENGTH;
        act.add(actionEnque);
        OFFlowMod fm = (OFFlowMod) sw.getInputStream().getMessageFactory()
                .getMessage(OFType.FLOW_MOD);
        fm.setBufferId(-1).setIdleTimeout((short) 100)
                .setHardTimeout((short) 100)
                .setOutPort((short) OFPort.OFPP_ALL.getValue()).setMatch(match)
                .setActions(act).setLength(U16.t(flowModLength));
        sw.getOutputStream().write(fm);

        /*
         * TODO The code below is used in the original code of Beacon Openflow,
         * we need study better what this means and if we really need this.
         */

        OFAction action = new OFActionOutput(outPort);
        fm.setActions(Collections.singletonList((OFAction) action));

        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            /**
             * EXTRA CREDIT: This is a corner case, the packet was not buffered
             * at the switch so it must be sent as an OFPacketOut after sending
             * the OFFlowMod
             */
            OFPacketOut po = new OFPacketOut();
            action = new OFActionOutput(outPort);
            po.setActions(Collections.singletonList(action));
            po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
            po.setInPort(pi.getInPort());
            po.setPacketData(pi.getPacketData());
            sw.getOutputStream().write(po);
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
             * TODO ERRO - ERROR - sometimes appear switches that aren't really of the network (ghosts)!
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
        for (IOFSwitch s : switches) {
            IOFSwitch sw = beaconProvider.getSwitches().get(s.getId());
            deleteAllFlowMod(sw);
        }
    }

    // ---------- NO NEED TO EDIT ANYTHING BELOW THIS LINE ----------

    /**
     * Ensure there is a MAC to port table per switch
     * 
     * @param sw
     */
    private void initMACTable(IOFSwitch sw) {
        Map<Long, Short> macTable = macTables.get(sw);
        if (macTable == null) {
            macTable = new HashMap<Long, Short>();
            macTables.put(sw, macTable);
        }
    }

    @Override
    public void addedSwitch(IOFSwitch sw) {
        /*
         * TODO - Can we use this instead than use the method that discovery all switches on
         * the network? Here we can use a list and put all registered switches
         * there, this will avoid to send OpenFlow message on network and can be
         * more fast and produce less overhead!
         */
        //registredSwitches.addSwitchOnListOfRegisteredSwitches(sw);
    }

    @Override
    public void removedSwitch(IOFSwitch sw) {
        macTables.remove(sw);
        //registredSwitches.removeSwitchOnListOfRegisteredSwitches(sw);
    }

    /**
     * @param beaconProvider
     *            the beaconProvider to set
     */
    public void setBeaconProvider(IBeaconProvider beaconProvider) {
        this.beaconProvider = beaconProvider;
    }

    public void startUp() {
        log.trace("=======================Starting=======================");
        // beaconProvider.addOFMessageListener(OFType.PACKET_IN, this);
        beaconProvider.addOFMessageListener(OFType.PACKET_IN, this);
        beaconProvider.addOFMessageListener(OFType.STATS_REPLY, this);
        beaconProvider.addOFSwitchListener(this);

        // Thread responsible for construct the attacks memory
        // memoryAttacks.startUp();
        if(disableOfIDPS!=1) {
            
            if (disableOfIDPS_UseOfgetStatisticsFromNetwork != 1) {
                log.debug("\tStarting OpenFlow monitor statistics...");
                sensorOF.startUp(beaconProvider);
                sensorOF.start();
            } else {
                log.debug("\t!!!!!!!! ATTENTION, Of-IDPS won't get OpenFlow statistics, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS_UseOfgetStatisticsFromNetwork on LearningSwithTutorialSolution class..."); 
            }
            
            log.debug("\tStarting AUTONOMIC rules...");
            memoryAttacks.startUp(beaconProvider);
            memoryAttacks.start();
            
            if (disableOfIDPS_UseOfAlerts != 1 && disableOfIDPS_UseOfgetStatisticsFromNetwork !=1) {
                log.debug("\tStarting OpenFlow ANALYSIS...");
                analysisFlow.start();
            } else {
                log.debug("\t!!!!!!!! ATTENTION, Of-IDPS ALERT OPENFLOW STATISTICS IS DISABLED, then won't be able to generate autonomic rules based on OpenFlow data!!!!!!!  to change this setup to 0 (zero) the variableS disableOfIDPS_UseOfgetStatisticsFromNetwork and disableOfIDPS_UseOfAlerts on LearningSwithTutorialSolution class...");
            }
            
            
        } else {
            log.debug("\t!!!!!!!! ATTENTION, Of-IDPS DISABLE and AUTONOMIC RULES TOO!!!!!!!  to change this setup to 0 (zero) the variable disableOfIDPS on LearningSwithTutorialSolution class...");
        }

    }

    public void shutDown() {
        log.trace("Stopping");
        beaconProvider.removeOFMessageListener(OFType.PACKET_IN, this);
        beaconProvider.removeOFMessageListener(OFType.STATS_REPLY, this);
        beaconProvider.removeOFSwitchListener(this);
    }

    public String getName() {
        return "tutorial";
    }

}
