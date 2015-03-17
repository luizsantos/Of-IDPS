/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core.io.internal;

import java.io.IOException;
import java.nio.channels.SelectionKey;

/**
 * @author Rob Sherwood (rob.sherwood@stanford.edu)
 *
 */
public interface SelectListener {
    /**
     * Tell the select listener that an event took place on the passed object
     * @param key the key used on the select
     * @param arg some parameter passed by the caller when registering
     * @throws IOException
     */
    void handleEvent(SelectionKey key, Object arg) throws IOException;
}
