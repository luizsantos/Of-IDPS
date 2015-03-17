package org.openflow.protocol.action;

import org.openflow.util.U16;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFActionTransportLayerDestination extends OFActionTransportLayer {
    public OFActionTransportLayerDestination() {
        super();
        super.setType(OFActionType.SET_TP_DST);
        super.setLength((short) OFActionTransportLayer.MINIMUM_LENGTH);
    }

    @Override
    public String toString() {
        return "OFActionTransportLayerDestination [transportPort="
                + U16.f(transportPort) + "]";
    }
}
