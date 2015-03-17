/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core;

public enum OFSwitchState {
    DISCONNECTED,
    HELLO_SENT,
    FEATURES_REQUEST_SENT,
    DESCRIPTION_STATISTICS_REQUEST_SENT,
    GET_CONFIG_REQUEST_SENT,
    INITIALIZING,
    ACTIVE
}
