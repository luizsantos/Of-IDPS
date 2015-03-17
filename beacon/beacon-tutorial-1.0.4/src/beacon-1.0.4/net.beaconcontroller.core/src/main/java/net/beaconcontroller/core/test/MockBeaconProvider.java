/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core.test;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFInitializerListener;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;
import net.beaconcontroller.core.IOFSwitchListener;
import net.beaconcontroller.core.IOFMessageListener.Command;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class MockBeaconProvider implements IBeaconProvider {
    protected Logger log = LoggerFactory.getLogger(MockBeaconProvider.class);

    protected Map<OFType, List<IOFMessageListener>> listeners;
    protected List<IOFSwitchListener> switchListeners;
    protected Map<Long, IOFSwitch> switches;

    /**
     * 
     */
    public MockBeaconProvider() {
        listeners = new ConcurrentHashMap<OFType, List<IOFMessageListener>>();
        switches = new ConcurrentHashMap<Long, IOFSwitch>();
        switchListeners = new CopyOnWriteArrayList<IOFSwitchListener>();
    }

    public void addOFMessageListener(OFType type, IOFMessageListener listener) {
        if (!listeners.containsKey(type)) {
            listeners.put(type, new ArrayList<IOFMessageListener>());
        }
        listeners.get(type).add(listener);
    }

    public void removeOFMessageListener(OFType type, IOFMessageListener listener) {
        listeners.get(type).remove(listener);
    }

    /**
     * @return the listeners
     */
    public Map<OFType, List<IOFMessageListener>> getListeners() {
        return listeners;
    }

    /**
     * @param listeners the listeners to set
     */
    public void setListeners(Map<OFType, List<IOFMessageListener>> listeners) {
        this.listeners = listeners;
    }

    @Override
    public Map<Long, IOFSwitch> getSwitches() {
        return this.switches;
    }

    public void setSwitches(Map<Long, IOFSwitch> switches) {
        this.switches = switches;
    }

    @Override
    public void addOFSwitchListener(IOFSwitchListener listener) {
        switchListeners.add(listener);
    }

    @Override
    public void removeOFSwitchListener(IOFSwitchListener listener) {
        switchListeners.remove(listener);
    }

    public void dispatchMessage(IOFSwitch sw, OFMessage msg) {
        List<IOFMessageListener> listeners = this.listeners.get(msg.getType());
        if (listeners != null) {
            Command result = Command.CONTINUE;
            Iterator<IOFMessageListener> it = listeners.iterator();
            while (it.hasNext() && !Command.STOP.equals(result)) {
                try {
                    result = it.next().receive(sw, msg);
                } catch (IOException e) {
                    log.error("Failure processing handler", e);
                }
            }
        }
    }

    /**
     * @return the switchListeners
     */
    public List<IOFSwitchListener> getSwitchListeners() {
        return switchListeners;
    }

    @Override
    public void addOFInitializerListener(IOFInitializerListener listener) {
    }

    @Override
    public void removeOFInitializerListener(IOFInitializerListener listener) {
    }

    @Override
    public void initializerComplete(IOFSwitch sw, IOFInitializerListener listener) {
    }

    @Override
    public List<IOFInitializerListener> getInitializers() {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public InetAddress getListeningIPAddress() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getListeningPort() {
        // TODO Auto-generated method stub
        return 0;
    }
}
