/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Future;

import net.beaconcontroller.core.io.OFMessageSafeOutStream;

import org.openflow.io.OFMessageInStream;
import org.openflow.protocol.OFFeaturesReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.OFDescriptionStatistics;
import org.openflow.protocol.statistics.OFStatistics;

/**
 *
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface IOFSwitch {
    /**
     *
     * @return
     */
    public OFMessageInStream getInputStream();

    /**
     *
     * @return
     */
    public OFMessageSafeOutStream getOutputStream();

    /**
     *
     * @return
     */
    public SocketChannel getSocketChannel();

    /**
     * Returns the cached OFFeaturesReply message returned by the switch during
     * the initial handshake.
     * @return
     */
    public OFFeaturesReply getFeaturesReply();

    /**
     * Set the OFFeaturesReply message returned by the switch during initial
     * handshake.
     * @param featuresReply
     */
    public void setFeaturesReply(OFFeaturesReply featuresReply);

    /**
     * Get the datapathId of the switch
     * @return
     */
    public long getId();

    /**
     * Retrieves attributes of this switch
     * @return
     */
    public ConcurrentMap<Object, Object> getAttributes();

    /**
     * Holds switch local attributes, similar to getAttributes, however
     * there is no synchronization on this map.
     * @return
     */
    public Map<Object, Object> getLocal();

    /**
     * Retrieves the date the switch connected to this controller
     * @return the date
     */
    public Date getConnectedSince();

    /**
     * Returns the next available transaction id
     * @return
     */
    public int getNextTransactionId();

    /**
     * Returns the time in milliseconds since the epoch of the last received
     * message from this switch.
     * @return
     */
    public long getLastReceivedMessageTime();

    /**
     * Sets the time of the most recently received message from this switch in
     * milliseconds since the epoch
     * @param epochMS time in milliseconds since the epoch
     */
    public void setLastReceivedMessageTime(long epochMS);

    /**
     * Returns a Future object that can be used to retrieve the asynchronous
     * OFStatisticsReply when it is available.
     *
     * @param request statistics request
     * @return Future object wrapping OFStatisticsReply
     * @throws IOException 
     */
    public Future<List<OFStatistics>> getStatistics(OFStatisticsRequest request)
            throws IOException;

    /**
     * Returns the state the switch is currently in.
     * @return the current state
     */
    public OFSwitchState getState();

    /**
     * Returns the description statistics for this switch
     * @return
     */
    public OFDescriptionStatistics getDescriptionStatistics();
}
