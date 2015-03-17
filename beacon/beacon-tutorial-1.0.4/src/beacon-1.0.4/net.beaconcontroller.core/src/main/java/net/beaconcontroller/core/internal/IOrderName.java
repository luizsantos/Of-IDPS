/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core.internal;

public interface IOrderName<T> {
    /**
     * Returns the name for this object used in the ordering String
     * @param obj
     * @return
     */
    public String get(T obj);
}
