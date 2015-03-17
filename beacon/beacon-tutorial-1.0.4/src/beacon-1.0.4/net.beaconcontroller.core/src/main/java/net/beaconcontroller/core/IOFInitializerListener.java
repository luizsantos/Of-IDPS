/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core;

import java.io.IOException;

import org.openflow.protocol.OFMessage;

/**
 * This interface is used by listeners that need to perform switch interaction
 * prior to making the switch generally available to IOFMessageListeners. On
 * startup each implementer of this class should register with
 * {@link IBeaconProvider#addOFInitListener(IOFMessageListener)}.
 *
 * When a switch completes the core's initialization it transits into a state
 * where incoming OpenFlow messages are sent to one listener at a time.  Once
 * a listener completes initialization for a switch it calls
 * {@link IBeaconProvider#initializerComplete(IOFSwitch, IOFMessageListener)}
 * which removes this listener from the list of initialization listeners
 * for the specified switch.  At this point incoming OpenFlow messages are sent
 * to the next listener in sequence, or the switch transits state to
 * being active.
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface IOFInitializerListener {
    /**
     * Called when it is this initializer's turn to hold the initializer 'lock'
     * on the switch.  Do not perform any long running computation from this
     * method, create a thread to handle such computation.
     * @param sw
     */
    public void initializerStart(IOFSwitch sw);

    /**
     * This is the method Beacon uses to call initialization listeners with
     * incoming OpenFlow messages
     * @param sw the OpenFlow switch that sent this message
     * @param msg the message
     * @throws IOException
     */
    public void initializerReceive(IOFSwitch sw, OFMessage msg) throws IOException;

    /**
     * The name assigned to this initialization listener
     * @return
     */
    public String getInitializerName();
}
