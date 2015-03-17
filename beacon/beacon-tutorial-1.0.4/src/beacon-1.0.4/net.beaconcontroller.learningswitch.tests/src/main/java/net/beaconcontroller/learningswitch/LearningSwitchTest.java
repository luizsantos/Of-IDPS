/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.learningswitch;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.core.io.OFMessageSafeOutStream;
import net.beaconcontroller.core.test.MockBeaconProvider;
import net.beaconcontroller.packet.Data;
import net.beaconcontroller.packet.Ethernet;
import net.beaconcontroller.packet.IPacket;
import net.beaconcontroller.packet.IPv4;
import net.beaconcontroller.packet.UDP;
import net.beaconcontroller.test.BeaconTestCase;
import net.beaconcontroller.util.LongShortHopscotchHashMap;

import org.junit.Before;
import org.junit.Test;
import org.openflow.io.OFMessageInStream;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketIn.OFPacketInReason;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.factory.BasicFactory;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class LearningSwitchTest extends BeaconTestCase {
    protected OFPacketIn packetIn;
    protected IPacket testPacket;
    protected byte[] testPacketSerialized;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        // Build our test packet
        this.testPacket = new Ethernet()
            .setDestinationMACAddress("00:11:22:33:44:55")
            .setSourceMACAddress("00:44:33:22:11:00")
            .setEtherType(Ethernet.TYPE_IPv4)
            .setPayload(
                new IPv4()
                .setTtl((byte) 128)
                .setSourceAddress("192.168.1.1")
                .setDestinationAddress("192.168.1.2")
                .setPayload(new UDP()
                            .setSourcePort((short) 5000)
                            .setDestinationPort((short) 5001)
                            .setPayload(new Data(new byte[] {0x01}))));
        this.testPacketSerialized = testPacket.serialize();

        // Build the PacketIn
        this.packetIn = new OFPacketIn()
            .setBufferId(-1)
            .setInPort((short) 1)
            .setPacketData(this.testPacketSerialized)
            .setReason(OFPacketInReason.NO_MATCH)
            .setTotalLength((short) this.testPacketSerialized.length);
    }

    protected LearningSwitch getLearningSwitch() {
        return (LearningSwitch) getApplicationContext().getBean("learningSwitch");
    }

    protected MockBeaconProvider getMockBeaconProvider() {
        return (MockBeaconProvider) getApplicationContext().getBean("mockBeaconProvider");
    }

    @Test
    public void testFlood() throws Exception {
        MockBeaconProvider mockBeaconProvider = getMockBeaconProvider();

        // build our expected flooded packetOut
        OFPacketOut po = new OFPacketOut()
            .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue())}))
            .setBufferId(-1)
            .setInPort((short)1)
            .setPacketData(this.testPacketSerialized);

        // Mock up our expected behavior
        IOFSwitch mockSwitch = createMock(IOFSwitch.class);
        OFMessageSafeOutStream mockStream = createMock(OFMessageSafeOutStream.class);
        Map<Object,Object> local = new HashMap<Object, Object>();
        expect(mockSwitch.getOutputStream()).andReturn(mockStream);
        expect(mockSwitch.getLocal()).andReturn(local).anyTimes();
        mockStream.write(po);

        // Start recording the replay on the mocks
        replay(mockSwitch, mockStream);
        // Get the listener and trigger the packet in
        IOFMessageListener listener = mockBeaconProvider.getListeners().get(
                OFType.PACKET_IN).get(0);
        listener.receive(mockSwitch, this.packetIn);

        // Verify the replay matched our expectations
        verify(mockSwitch, mockStream);

        // Verify the MAC table inside the switch
        assertEquals(1, ((LongShortHopscotchHashMap) mockSwitch.getLocal().get(LearningSwitch.class)).get(
                Ethernet.toLong(Ethernet.toMACAddress("00:44:33:22:11:00"))));
    }

    @Test
    public void testFlowMod() throws Exception {
        MockBeaconProvider mockBeaconProvider = getMockBeaconProvider();

        // tweak the test packet in since we need a bufferId
        this.packetIn.setBufferId(50);

        // build expected flow mod
        OFMessage fm = new OFFlowMod()
            .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort((short) 2)}))
            .setBufferId(50)
            .setCommand(OFFlowMod.OFPFC_ADD)
            .setIdleTimeout((short) 5)
            .setMatch(new OFMatch().loadFromPacket(testPacketSerialized, (short) 1));

        // Mock up our expected behavior
        IOFSwitch mockSwitch = createMock(IOFSwitch.class);
        OFMessageInStream mockInStream = createMock(OFMessageInStream.class);
        OFMessageSafeOutStream mockStream = createMock(OFMessageSafeOutStream.class);
        Map<Object,Object> local = new HashMap<Object, Object>();
        expect(mockSwitch.getInputStream()).andReturn(mockInStream).anyTimes();
        expect(mockInStream.getMessageFactory()).andReturn(new BasicFactory()).anyTimes();
        expect(mockSwitch.getOutputStream()).andReturn(mockStream);
        expect(mockSwitch.getLocal()).andReturn(local).anyTimes();
        mockStream.write(fm);

        // Start recording the replay on the mocks
        replay(mockSwitch, mockStream, mockInStream);

        // Populate the MAC table
        mockSwitch.getLocal().put(LearningSwitch.class, new LongShortHopscotchHashMap());
        ((LongShortHopscotchHashMap) mockSwitch.getLocal().get(LearningSwitch.class)).put(
                Ethernet.toLong(Ethernet.toMACAddress("00:11:22:33:44:55")),
                (short) 2);

        // Get the listener and trigger the packet in
        IOFMessageListener listener = mockBeaconProvider.getListeners().get(
                OFType.PACKET_IN).get(0);
        listener.receive(mockSwitch, this.packetIn);

        // Verify the replay matched our expectations
        verify(mockSwitch, mockStream, mockInStream);

        // Verify the MAC table inside the switch
        assertEquals(1, ((LongShortHopscotchHashMap) mockSwitch.getLocal().get(LearningSwitch.class)).get(
                Ethernet.toLong(Ethernet.toMACAddress("00:44:33:22:11:00"))));
    }
}
