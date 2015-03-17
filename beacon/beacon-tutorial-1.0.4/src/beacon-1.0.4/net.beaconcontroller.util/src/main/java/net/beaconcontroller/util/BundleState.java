/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.util;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public enum BundleState {
    ACTIVE              (32),
    INSTALLED           (2),
    RESOLVED            (4),
    STARTING            (8),
    STOPPING            (16),
    UNINSTALLED         (1);

    protected int value;

    private BundleState(int value) {
        this.value = value;
    }

    /**
     * @return the value
     */
    public int getValue() {
        return value;
    }

    public static BundleState getState(int value) {
        switch (value) {
            case 32:
                return ACTIVE;
            case 2:
                return INSTALLED;
            case 4:
                return RESOLVED;
            case 8:
                return STARTING;
            case 16:
                return STOPPING;
            case 1:
                return UNINSTALLED;
        }
        return null;
    }
}
