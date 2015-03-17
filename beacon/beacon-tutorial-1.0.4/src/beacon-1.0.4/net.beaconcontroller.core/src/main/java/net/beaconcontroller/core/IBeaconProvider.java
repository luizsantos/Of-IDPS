/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFType;

/**
 * The interface exposed by the core bundle that allows you to interact
 * with connected switches.
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface IBeaconProvider {
    /**
     * Adds an initializer listener that will be used for each newly connecting
     * switch.
     * @param listener
     */
    public void addOFInitializerListener(IOFInitializerListener listener);

    /**
     * Removes an initializer listener from the list that is used for each
     * switch
     * @param listener
     */
    public void removeOFInitializerListener(IOFInitializerListener listener);

    /**
     * Once an initializer has initialized a switch it calls this method
     * which removes the initializer for the specified switch, sending
     * OFMessages to the next listener in sequence, or making the switch active
     * if the sequence for the specified switch becomes empty.
     * @param sw
     * @param listener
     */
    public void initializerComplete(IOFSwitch sw, IOFInitializerListener listener);

    /**
     * 
     * @param type
     * @param listener
     */
    public void addOFMessageListener(OFType type, IOFMessageListener listener);

    /**
     * 
     * @param type
     * @param listener
     */
    public void removeOFMessageListener(OFType type, IOFMessageListener listener);

    /**
     * Returns a read-only map of all OpenFlow switches in the ACTIVE state
     * @return the map of switches
     */
    public Map<Long, IOFSwitch> getSwitches();

    /**
     * Add a switch listener
     *
     * @param listener
     */
    public void addOFSwitchListener(IOFSwitchListener listener);

    /**
     * Remove a switch listener
     *
     * @param listener
     */
    public void removeOFSwitchListener(IOFSwitchListener listener);

    /**
     * Return a non-modifiable list of all current listeners
     *
     * @return listeners
     */
    public Map<OFType, List<IOFMessageListener>> getListeners();

    /**
     * Return a non-modifiable list of all registered initializers
     *
     * @return initializers
     */
    public List<IOFInitializerListener> getInitializers();

    /**
     * Returns an object containing the IP address that Beacon
     * is listening on for switch connections.
     *
     * @return
     */
    public InetAddress getListeningIPAddress();

    /**
     * Returns an object containing the port that Beacon
     * is listening on for switch connections.
     *
     * @return
     */
    public int getListeningPort();
}
