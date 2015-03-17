package org.openflow.protocol;

import java.nio.ByteBuffer;

/**
 * This message is created when reading from an OpenFlow stream that
 * delivers a message of an unknown type.  This class skips over the
 * data of the unknown message.
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFUnknownMessage extends OFMessage {

    @Override
    public void readFrom(ByteBuffer data) {
        super.readFrom(data);
        // Advance past unknown data
        if (super.length > MINIMUM_LENGTH) {
            data.position(data.position() + (super.length - MINIMUM_LENGTH));
        }
    }

    @Override
    public void writeTo(ByteBuffer data) {
        throw new RuntimeException("This message cannot be written to a stream");
    }
}
