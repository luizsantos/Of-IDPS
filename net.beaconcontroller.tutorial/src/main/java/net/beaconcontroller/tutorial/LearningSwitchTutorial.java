/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.tutorial;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.core.IOFSwitchListener;
import net.beaconcontroller.packet.Ethernet;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tutorial class used to teach how to build a simple layer 2 learning switch.
 *
 * @author David Erickson (daviderickson@cs.stanford.edu) - 10/14/12
 */
@SuppressWarnings("unused")
public class LearningSwitchTutorial implements IOFMessageListener, IOFSwitchListener {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorial.class);
    protected IBeaconProvider beaconProvider;
    protected Map<IOFSwitch, Map<Long,Short>> macTables =
        new HashMap<IOFSwitch, Map<Long,Short>>();

    public Command receive(IOFSwitch sw, OFMessage msg) throws IOException {
        initMACTable(sw);
        OFPacketIn pi = (OFPacketIn) msg;

        /**
         * This is the basic flood-based forwarding that is enabled.
         */
        forwardAsHub(sw, pi);

        /**
         * This is the layer 2 based switching you will create. Once you have
         * created the appropriate code in the forwardAsLearningSwitch method
         * (see below), comment out the above call to forwardAsHub, and
         * uncomment the call here to forwardAsLearningSwitch.
         */
        //forwardAsLearningSwitch(sw, pi);
        return Command.CONTINUE;
    }

    /**
     * EXAMPLE CODE: Floods the packet out all switch ports except the port it
     * came in on.
     *
     * @param sw the OpenFlow switch object
     * @param pi the OpenFlow Packet In object
     * @throws IOException
     */
    public void forwardAsHub(IOFSwitch sw, OFPacketIn pi) throws IOException {
        // Create the OFPacketOut OpenFlow object
        OFPacketOut po = new OFPacketOut();

        // Create an output action to flood the packet, put it in the OFPacketOut
        OFAction action = new OFActionOutput(OFPort.OFPP_FLOOD.getValue());
        po.setActions(Collections.singletonList(action));

        // Set the port the packet originally arrived on
        po.setInPort(pi.getInPort());

        // Reference the packet buffered at the switch by id
        po.setBufferId(pi.getBufferId());
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            /**
             * The packet was NOT buffered at the switch, therefore we must
             * copy the packet's data from the OFPacketIn to our new
             * OFPacketOut message.
             */
            po.setPacketData(pi.getPacketData());
        }
        // Send the OFPacketOut to the switch
        sw.getOutputStream().write(po);
    }

    /**
     * TODO: Learn the source MAC:port pair for each arriving packet. Next send
     * the packet out the port previously learned for the destination MAC, if it
     * exists. Otherwise flood the packet similarly to forwardAsHub.
     *
     * @param sw the OpenFlow switch object
     * @param pi the OpenFlow Packet In object
     * @throws IOException
     */
    public void forwardAsLearningSwitch(IOFSwitch sw, OFPacketIn pi) throws IOException {
        Map<Long,Short> macTable = macTables.get(sw);

        /**
         * START HERE: You'll find descriptions of what needs to be done below
         * here, and starter pseudo code. Your job is to uncomment and replace
         * the pseudo code with actual Java code.
         *
         * First build the OFMatch object that will be used to match packets
         * from this new flow. See the OFMatch and OFPacketIn class Javadocs,
         * which if you are using the tutorial archive, are in the apidocs
         * folder where you extracted it.
         */
        // OFMatch match = ...

        /**
         * Learn that the host with the source MAC address in this packet is
         * reachable at the port this packet arrived on. Put this source
         * MAC:port pair into the macTable object for future lookups. HINT: you
         * can use Ethernet.toLong to convert from byte[] to Long, which is the
         * key for the macTable Map object.
         */
        // macTable.put(...);
        // log.info("Learned MAC address {} is at port {}", macAddress, port);

        /**
         * Retrieve the port this packet should be sent out by getting the port
         * associated with the destination MAC address in this packet from the
         * macTable object.
         */
        // Short outPort = macTable...

        /**
         * If the outPort is known for the MAC address (the return value from
         * macTable is not null), then
         *      Phase 1: 
         *      Create and send an OFPacketOut, sending it to the outPort
         *      learned previously. After this is tested and works move to
         *      phase 2.
         *
         *      Phase 2:
         *      Instead of an OFPacketOut, create and send an OFFlowMod using
         *      the match created earlier from the packet, and send matched
         *      packets to the outPort.
         *      For extra credit, after sending the OFFlowMod, send an
         *      OFPacketOut, but only if the switch did not buffer the packet
         *      (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE), and be sure
         *      to set the OFPacketOut's data with the data in pi.
         *
         * Else if the outPort is not known (return value from macTable is
         * null), then use the forwardAsHub method to send an OFPacketOut that
         * floods out all ports except the port the packet came in.
         * 
         */
        // if (outPort != null) {
            // Phase 1:
            // OFPacketOut po = ...
            // ... fill in po, unicast to outPort
            // ... send po to the switch
            //
            // Phase 2:
            // Comment out the code from phase 1
            // OFFlowMod fm = ...
            // ... fill in fm
            // ... send fm to the switch
            // Extra credit:
            // if (...) {
            //      OFPacketOut po = ...
            //      ... fill in po, unicast to outPort
            //      ... set po's data from pi's data
            //      ... send po to the switch
            // }
        //} else {
            // forwardAsHub(sw, pi);
        //}
    }

    // ---------- NO NEED TO EDIT ANYTHING BELOW THIS LINE ----------

    /**
     * Ensure there is a MAC to port table per switch
     * @param sw
     */
    private void initMACTable(IOFSwitch sw) {
        Map<Long,Short> macTable = macTables.get(sw);
        if (macTable == null) {
            macTable = new HashMap<Long,Short>();
            macTables.put(sw, macTable);
        }
    }

    @Override
    public void addedSwitch(IOFSwitch sw) {
    }

    @Override
    public void removedSwitch(IOFSwitch sw) {
        macTables.remove(sw);
    }

    /**
     * @param beaconProvider the beaconProvider to set
     */
    public void setBeaconProvider(IBeaconProvider beaconProvider) {
        this.beaconProvider = beaconProvider;
    }

    public void startUp() {
        log.trace("Starting");
        beaconProvider.addOFMessageListener(OFType.PACKET_IN, this);
        beaconProvider.addOFSwitchListener(this);
    }

    public void shutDown() {
        log.trace("Stopping");
        beaconProvider.removeOFMessageListener(OFType.PACKET_IN, this);
        beaconProvider.removeOFSwitchListener(this);
    }

    public String getName() {
        return "tutorial";
    }
}
