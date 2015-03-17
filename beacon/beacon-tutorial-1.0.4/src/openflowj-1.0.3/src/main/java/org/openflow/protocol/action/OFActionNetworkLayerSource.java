package org.openflow.protocol.action;

import org.openflow.protocol.OFMatch;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFActionNetworkLayerSource extends OFActionNetworkLayerAddress {
    public OFActionNetworkLayerSource() {
        super();
        super.setType(OFActionType.SET_NW_SRC);
        super.setLength((short) OFActionNetworkLayerAddress.MINIMUM_LENGTH);
    }

    @Override
    public String toString() {
        return "OFActionNetworkLayerSource [networkAddress="
                + OFMatch.ipToString(networkAddress) + "]";
    }
}
