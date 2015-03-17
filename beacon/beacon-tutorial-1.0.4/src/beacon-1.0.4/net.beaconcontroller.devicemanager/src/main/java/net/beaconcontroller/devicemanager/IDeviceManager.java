/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.devicemanager;

import java.util.List;

/**
 * Used to interact with DeviceManager implementations
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface IDeviceManager {
    /**
     * Returns a device for the given data layer address
     * @param address
     * @return
     */
    public Device getDeviceByDataLayerAddress(byte[] address);

    /**
     * Returns a device for the given network layer address
     * @param address
     * @return
     */
    public Device getDeviceByNetworkLayerAddress(Integer address);

    /**
     * Returns a list of all known devices in the system
     * @return
     */
    public List<Device> getDevices();
}
