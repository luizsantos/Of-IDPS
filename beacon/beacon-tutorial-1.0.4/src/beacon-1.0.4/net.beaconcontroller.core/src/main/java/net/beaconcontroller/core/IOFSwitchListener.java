/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core;

/**
 *
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface IOFSwitchListener {

    /**
     * Fired when a switch is connected to the controller, and has sent
     * a features reply.
     * @param sw
     */
    public void addedSwitch(IOFSwitch sw);

    /**
     * Fired when a switch is disconnected from the controller.
     * @param sw
     */
    public void removedSwitch(IOFSwitch sw);
    
    /**
     * The name assigned to this listener
     * @return
     */
    public String getName();
}
