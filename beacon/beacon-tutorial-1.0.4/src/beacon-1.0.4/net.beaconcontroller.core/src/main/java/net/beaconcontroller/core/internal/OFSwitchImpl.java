/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core.internal;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.OFSwitchState;
import net.beaconcontroller.core.io.OFMessageSafeOutStream;

import org.openflow.io.OFMessageInStream;
import org.openflow.protocol.OFFeaturesReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.statistics.OFDescriptionStatistics;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFSwitchImpl implements IOFSwitchExt {
    protected static Logger log = LoggerFactory.getLogger(OFSwitchImpl.class);
    protected ConcurrentMap<Object, Object> attributes;
    protected IBeaconProvider beaconProvider;
    protected Date connectedSince;
    protected OFDescriptionStatistics descriptionStatistics;
    protected OFFeaturesReply featuresReply;
    protected OFMessageInStream inStream;
    protected Map<Object, Object> local;
    protected OFMessageSafeOutStream outStream;
    protected long lastReceivedMessageTime;
    protected SocketChannel socketChannel;
    protected volatile OFSwitchState state;
    protected AtomicInteger transactionIdSource;

    public OFSwitchImpl() {
        this.attributes = new ConcurrentHashMap<Object, Object>();
        this.connectedSince = new Date();
        this.lastReceivedMessageTime = this.connectedSince.getTime();
        this.local = new HashMap<Object, Object>();
        this.transactionIdSource = new AtomicInteger();
    }

    public SocketChannel getSocketChannel() {
        return this.socketChannel;
    }

    public void setSocketChannel(SocketChannel channel) {
        this.socketChannel = channel;
    }

    public OFMessageInStream getInputStream() {
        return inStream;
    }

    public OFMessageSafeOutStream getOutputStream() {
        return outStream;
    }

    public void setInputStream(OFMessageInStream stream) {
        this.inStream = stream;
    }

    public void setOutputStream(OFMessageSafeOutStream stream) {
        this.outStream = stream;
    }

    /**
     *
     */
    public OFFeaturesReply getFeaturesReply() {
        return this.featuresReply;
    }

    /**
     * @param featuresReply the featuresReply to set
     */
    public void setFeaturesReply(OFFeaturesReply featuresReply) {
        this.featuresReply = featuresReply;
    }

    @Override
    public long getId() {
        if (this.featuresReply == null)
            throw new RuntimeException("Features reply has not yet been set");
        return this.featuresReply.getDatapathId();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "OFSwitchImpl [" + socketChannel.socket() + " DPID[" + ((featuresReply != null) ? HexString.toHexString(featuresReply.getDatapathId()) : "?") + "]]";
    }

    @Override
    public ConcurrentMap<Object, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Date getConnectedSince() {
        return connectedSince;
    }

    @Override
    public int getNextTransactionId() {
        return this.transactionIdSource.incrementAndGet();
    }

    @Override
    public Future<List<OFStatistics>> getStatistics(OFStatisticsRequest request) throws IOException {
        request.setXid(getNextTransactionId());
        OFStatisticsFuture future = new OFStatisticsFuture(beaconProvider, this, request.getXid());
        this.beaconProvider.addOFMessageListener(OFType.STATS_REPLY, future);
        this.beaconProvider.addOFSwitchListener(future);
        this.getOutputStream().write(request);
        return future;
    }

    /**
     * @param beaconProvider the beaconProvider to set
     */
    public void setBeaconProvider(IBeaconProvider beaconProvider) {
        this.beaconProvider = beaconProvider;
    }

    @Override
    public long getLastReceivedMessageTime() {
        return lastReceivedMessageTime;
    }

    @Override
    public void setLastReceivedMessageTime(long epochMS) {
        this.lastReceivedMessageTime = epochMS;
    }

    @Override
    public OFSwitchState getState() {
        return state;
    }

    @Override
    public void transitionToState(OFSwitchState state) {
        if (log.isDebugEnabled())
            log.debug("Switch {} transitioning from state {} to {}",
                    new Object[] { this, this.state, state });
        this.state = state;
    }

    /**
     * @return the descriptionStatistics
     */
    @Override
    public OFDescriptionStatistics getDescriptionStatistics() {
        return descriptionStatistics;
    }

    /**
     * @param descriptionStatistics the descriptionStatistics to set
     */
    @Override
    public void setDescriptionStatistics(
            OFDescriptionStatistics descriptionStatistics) {
        this.descriptionStatistics = descriptionStatistics;
    }

    @Override
    public Map<Object, Object> getLocal() {
        return local;
    }
}
