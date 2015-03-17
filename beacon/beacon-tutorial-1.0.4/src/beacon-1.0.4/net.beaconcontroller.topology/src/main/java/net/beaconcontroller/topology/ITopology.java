/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.topology;

import java.util.Map;

/**
 *
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface ITopology {
    /**
     * Query to determine if the specified switch id and port tuple are
     * connected to another switch or not.  If so, this means the link
     * is passing LLDPs properly between two OpenFlow switches.
     * @param idPort
     * @return
     */
    public boolean isInternal(SwitchPortTuple idPort);

    /**
     * Retrieves a map of all known link connections between OpenFlow switches
     * and the last time each link was known to be functioning
     * @return
     */
    public Map<LinkTuple, Long> getLinks();
}
