/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core.internal;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.Socket;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.OFSwitchState;
import net.beaconcontroller.core.IOFMessageListener.Command;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.core.io.internal.IOLoop;
import net.beaconcontroller.core.io.internal.OFStream;
import net.beaconcontroller.core.test.MockBeaconProvider;
import net.beaconcontroller.test.BeaconTestCase;

import org.junit.Test;
import org.openflow.protocol.OFFeaturesReply;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFType;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class ControllerTest extends BeaconTestCase {
    protected Controller getController() {
        return (Controller) getApplicationContext().getBean("controller");
    }

    protected OFStatisticsReply getStatisticsReply(int transactionId,
            int count, boolean moreReplies) {
        OFStatisticsReply sr = new OFStatisticsReply();
        sr.setXid(transactionId);
        sr.setStatisticType(OFStatisticsType.FLOW);
        List<OFStatistics> statistics = new ArrayList<OFStatistics>();
        for (int i = 0; i < count; ++i) {
            statistics.add(new OFFlowStatisticsReply());
        }
        sr.setStatistics(statistics);
        if (moreReplies)
            sr.setFlags((short) 1);
        return sr;
    }

    /**
     * Verify that our callbacks are ordered with respect to the order specified
     * @throws Exception
     */
    @Test
    public void testCallbackOrderingBase() throws Exception {
        testCallbackOrdering(new String[] {"2"}, new String[] {"2"});
        testCallbackOrdering(new String[] {"3"}, new String[] {"3"});
        testCallbackOrdering(new String[] {"1","2"}, new String[] {"1","2"});
        testCallbackOrdering(new String[] {"2","1"}, new String[] {"1","2"});
        testCallbackOrdering(new String[] {"2","3"}, new String[] {"2","3"});
        testCallbackOrdering(new String[] {"3","2"}, new String[] {"2","3"});
        testCallbackOrdering(new String[] {"1","2","3"}, new String[] {"1","2","3"});
        testCallbackOrdering(new String[] {"1","3","2"}, new String[] {"1","2","3"});
        testCallbackOrdering(new String[] {"2","1","3"}, new String[] {"1","2","3"});
        testCallbackOrdering(new String[] {"2","3","1"}, new String[] {"1","2","3"});
        testCallbackOrdering(new String[] {"3","1","2"}, new String[] {"1","2","3"});
        testCallbackOrdering(new String[] {"3","2","1"}, new String[] {"1","2","3"});
    }

    protected void testCallbackOrdering(String[] addOrder, String[] verifyOrder) throws Exception {
        Controller controller = getController();
        controller.getMessageListeners().remove(OFType.PACKET_IN);
        Map<String,String> callbackOrdering = new HashMap<String,String>();
        callbackOrdering.put("PACKET_IN", "test1,test2");
        controller.setCallbackOrdering(callbackOrdering);

        IOFMessageListener test1 = createMock(IOFMessageListener.class);
        expect(test1.getName()).andReturn("test1").anyTimes();
        IOFMessageListener test2 = createMock(IOFMessageListener.class);
        expect(test2.getName()).andReturn("test2").anyTimes();
        IOFMessageListener test3 = createMock(IOFMessageListener.class);
        expect(test3.getName()).andReturn("test3").anyTimes();

        replay(test1, test2, test3);
        for (String o : addOrder) {
            if ("1".equals(o)) {
                controller.addOFMessageListener(OFType.PACKET_IN, test1);
            } else if ("2".equals(o)) {
                controller.addOFMessageListener(OFType.PACKET_IN, test2);
            } else {
                controller.addOFMessageListener(OFType.PACKET_IN, test3);
            }
        }

        verify(test1, test2, test3);
        for (int i = 0; i < verifyOrder.length; ++i) {
            String o = verifyOrder[i];
            if ("1".equals(o)) {
                assertEquals("test1", controller.getMessageListeners().get(OFType.PACKET_IN).get(i).getName());
            } else if ("2".equals(o)) {
                assertEquals("test2", controller.getMessageListeners().get(OFType.PACKET_IN).get(i).getName());
            } else {
                assertEquals("test3", controller.getMessageListeners().get(OFType.PACKET_IN).get(i).getName());
            }
        }
    }

    /**
     * Verify that a listener can throw an exception and not ruin further
     * execution, and verify that the Commands STOP and CONTINUE are honored.
     * @throws Exception
     */
    @Test
    public void testHandleMessages() throws Exception {
        Controller controller = getController();
        controller.getMessageListeners().remove(OFType.PACKET_IN);
        Map<String,String> callbackOrdering = new HashMap<String,String>();
        callbackOrdering.put("PACKET_IN", "test1,test2");
        controller.setCallbackOrdering(callbackOrdering);

        IOFSwitchExt sw = createMock(IOFSwitchExt.class);
        OFStream inputStream = createMock(OFStream.class);
        expect(sw.getInputStream()).andReturn(inputStream).anyTimes();
        expect(inputStream.getWriteFailure()).andReturn(false).anyTimes();
        expect(sw.getFeaturesReply()).andReturn(new OFFeaturesReply()).anyTimes();
        expect(sw.getState()).andReturn(OFSwitchState.ACTIVE).anyTimes();
        OFPacketIn pi = new OFPacketIn();
        IOFMessageListener test1 = createMock(IOFMessageListener.class);
        expect(test1.getName()).andReturn("test1").anyTimes();
        expect(test1.receive(sw, pi)).andThrow(new RuntimeException("Catch me!"));
        IOFMessageListener test2 = createMock(IOFMessageListener.class);
        expect(test2.getName()).andReturn("test2").anyTimes();
        expect(test2.receive(sw, pi)).andReturn(Command.CONTINUE);

        replay(test1, test2, sw, inputStream);
        controller.addOFMessageListener(OFType.PACKET_IN, test1);
        controller.addOFMessageListener(OFType.PACKET_IN, test2);
        controller.handleMessages(sw, Arrays.asList(new OFMessage[] {pi}));
        verify(test1, test2, sw, inputStream);

        // verify STOP works
        reset(test1, test2, sw, inputStream);
        expect(sw.getInputStream()).andReturn(inputStream).anyTimes();
        expect(inputStream.getWriteFailure()).andReturn(false).anyTimes();
        expect(test1.receive(sw, pi)).andReturn(Command.STOP);
        expect(sw.getFeaturesReply()).andReturn(new OFFeaturesReply()).anyTimes();
        expect(sw.getState()).andReturn(OFSwitchState.ACTIVE).anyTimes();
        replay(test1, test2, sw, inputStream);
        controller.handleMessages(sw, Arrays.asList(new OFMessage[] {pi}));
        verify(test1, test2, sw, inputStream);
    }

    /**
     * This test verifies that a switch that is not yet active will be correctly
     * tested for liveness and removed if necessary
     * @throws Exception
     */
    @Test
    public void testLiveness() throws Exception {
        Controller controller = getController();
        IOFSwitchExt sw = createMock(IOFSwitchExt.class);
        SocketChannel sc = createMock(SocketChannel.class);
        Socket sock = createMock(Socket.class);
        OFStream inputStream = createMock(OFStream.class);
        SelectionKey key = createMock(SelectionKey.class);
        IOLoop ioLoop = createMock(IOLoop.class);

        expect(sw.getLastReceivedMessageTime()).andReturn(0L).atLeastOnce();
        expect(sw.getInputStream()).andReturn(inputStream).anyTimes();
        expect(inputStream.getKey()).andReturn(key).atLeastOnce();
        expect(sw.getFeaturesReply()).andReturn(null).anyTimes();
        expect(sw.getState()).andReturn(OFSwitchState.HELLO_SENT).anyTimes();
        expect(sw.getSocketChannel()).andReturn(sc).atLeastOnce();
        expect(sc.socket()).andReturn(sock).atLeastOnce();
        expect(inputStream.getIOLoop()).andReturn(ioLoop).atLeastOnce();
        sw.transitionToState(OFSwitchState.DISCONNECTED);
        key.cancel();
        ioLoop.removeStream(inputStream);

        replay(sw, sc, inputStream, key, ioLoop);
        assertFalse(controller.getAllSwitches().contains(sw));
        controller.addSwitch(sw);
        assertTrue(controller.getAllSwitches().contains(sw));
        Thread.sleep(Controller.LIVENESS_POLL_INTERVAL*2);
        verify(sw, sc, inputStream, key, ioLoop);
        assertFalse(controller.getAllSwitches().contains(sw));
    }

    /**
     * This test verifies that a switch that is active will be correctly
     * tested for liveness and removed if necessary
     * @throws Exception
     */
    @Test
    public void testLivenessActive() throws Exception {
        Controller controller = getController();
        IOFSwitchExt sw = createMock(IOFSwitchExt.class);
        SocketChannel sc = createMock(SocketChannel.class);
        Socket sock = createMock(Socket.class);
        OFStream inputStream = createMock(OFStream.class);
        SelectionKey key = createMock(SelectionKey.class);
        IOLoop ioLoop = createMock(IOLoop.class);

        expect(sw.getLastReceivedMessageTime()).andReturn(0L).atLeastOnce();
        expect(sw.getInputStream()).andReturn(inputStream).anyTimes();
        expect(inputStream.getKey()).andReturn(key).atLeastOnce();
        expect(sw.getFeaturesReply()).andReturn(new OFFeaturesReply()).anyTimes();
        expect(sw.getState()).andReturn(OFSwitchState.ACTIVE).anyTimes();
        expect(sw.getSocketChannel()).andReturn(sc).atLeastOnce();
        expect(sw.getId()).andReturn(1L).atLeastOnce();
        expect(sc.socket()).andReturn(sock).atLeastOnce();
        expect(inputStream.getIOLoop()).andReturn(ioLoop).atLeastOnce();
        sw.transitionToState(OFSwitchState.DISCONNECTED);
        key.cancel();
        ioLoop.removeStream(inputStream);

        replay(sw, sc, inputStream, key, ioLoop);
        assertFalse(controller.getAllSwitches().contains(sw));
        assertFalse(controller.getSwitches().containsKey(1L));
        controller.addSwitch(sw);
        controller.addActiveSwitch(sw);
        assertTrue(controller.getAllSwitches().contains(sw));
        assertEquals(sw, controller.getSwitches().get(1L));
        Thread.sleep(Controller.LIVENESS_POLL_INTERVAL*2);
        verify(sw, sc, inputStream, key, ioLoop);
        assertFalse(controller.getAllSwitches().contains(sw));
        assertFalse(controller.getSwitches().containsKey(1L));
    }

    public class FutureFetcher<E> implements Runnable {
        public E value;
        public Future<E> future;

        public FutureFetcher(Future<E> future) {
            this.future = future;
        }

        @Override
        public void run() {
            try {
                value = future.get();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * @return the value
         */
        public E getValue() {
            return value;
        }

        /**
         * @return the future
         */
        public Future<E> getFuture() {
            return future;
        }
    }

    /**
     * 
     * @throws Exception
     */
    @Test
    public void testOFStatisticsFuture() throws Exception {
        // Test for a single stats reply
        MockBeaconProvider mbp = new MockBeaconProvider();
        IOFSwitch sw = createMock(IOFSwitch.class);
        OFStatisticsFuture sf = new OFStatisticsFuture(mbp, sw, 1);
        mbp.addOFMessageListener(OFType.STATS_REPLY, sf);
        mbp.addOFSwitchListener(sf);

        replay(sw);
        List<OFStatistics> stats;
        FutureFetcher<List<OFStatistics>> ff = new FutureFetcher<List<OFStatistics>>(sf);
        Thread t = new Thread(ff);
        t.start();
        mbp.dispatchMessage(sw, getStatisticsReply(1, 10, false));

        t.join();
        stats = ff.getValue();
        verify(sw);
        assertEquals(10, stats.size());
        assertEquals(0, mbp.getListeners().get(OFType.STATS_REPLY).size());
        assertEquals(0, mbp.getSwitchListeners().size());

        // Test multiple stats replies
        reset(sw);
        sf = new OFStatisticsFuture(mbp, sw, 1);
        mbp.addOFMessageListener(OFType.STATS_REPLY, sf);
        mbp.addOFSwitchListener(sf);

        replay(sw);
        ff = new FutureFetcher<List<OFStatistics>>(sf);
        t = new Thread(ff);
        t.start();
        mbp.dispatchMessage(sw, getStatisticsReply(1, 10, true));
        mbp.dispatchMessage(sw, getStatisticsReply(1, 5, false));
        t.join();

        stats = sf.get();
        verify(sw);
        assertEquals(15, stats.size());
        assertEquals(0, mbp.getListeners().get(OFType.STATS_REPLY).size());
        assertEquals(0, mbp.getSwitchListeners().size());

        // Test cancellation
        reset(sw);
        sf = new OFStatisticsFuture(mbp, sw, 1);
        mbp.addOFMessageListener(OFType.STATS_REPLY, sf);
        mbp.addOFSwitchListener(sf);

        replay(sw);
        ff = new FutureFetcher<List<OFStatistics>>(sf);
        t = new Thread(ff);
        t.start();
        sf.cancel(true);
        t.join();

        stats = sf.get();
        verify(sw);
        assertEquals(0, stats.size());
        assertEquals(0, mbp.getListeners().get(OFType.STATS_REPLY).size());
        assertEquals(0, mbp.getSwitchListeners().size());

        // Test self timeout
        reset(sw);
        sf = new OFStatisticsFuture(mbp, sw, 1, 3, TimeUnit.SECONDS);
        mbp.addOFMessageListener(OFType.STATS_REPLY, sf);
        mbp.addOFSwitchListener(sf);

        replay(sw);
        ff = new FutureFetcher<List<OFStatistics>>(sf);
        t = new Thread(ff);
        t.start();
        t.join(5000);

        stats = sf.get();
        verify(sw);
        assertEquals(0, stats.size());
        assertEquals(0, mbp.getListeners().get(OFType.STATS_REPLY).size());
        assertEquals(0, mbp.getSwitchListeners().size());
    }
}
