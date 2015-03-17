/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.packet;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class ICMP extends BasePacket {
    protected byte type;
    protected byte code;
    protected short checksum;
    protected byte[] data;


    /**
     * @return the type
     */
    public byte getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public ICMP setType(byte type) {
        this.type = type;
        return this;
    }

    /**
     * @return the code
     */
    public byte getCode() {
        return code;
    }

    /**
     * @param code the code to set
     */
    public ICMP setCode(byte code) {
        this.code = code;
        return this;
    }

    /**
     * @return the checksum
     */
    public short getChecksum() {
        return checksum;
    }

    /**
     * @param checksum the checksum to set
     */
    public ICMP setChecksum(short checksum) {
        this.checksum = checksum;
        return this;
    }

    /**
     * @return the data
     */
    public byte[] getData() {
        return data;
    }

    /**
     * @param data the data to set
     */
    public ICMP setData(byte[] data) {
        this.data = data;
        return this;
    }

    /**
     * Serializes the packet. Will compute and set the following fields if they
     * are set to specific values at the time serialize is called:
     *      -checksum : 0
     */
    public byte[] serialize() {
        int length = 4;
        if (this.data != null)
            length += this.data.length;

        byte[] data = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.put(this.type);
        bb.put(this.code);
        bb.putShort(this.checksum);
        if (this.data != null)
            bb.put(this.data);

        if (this.parent != null && this.parent instanceof IPv4)
            ((IPv4)this.parent).setProtocol(IPv4.PROTOCOL_ICMP);

        // compute checksum if needed
        if (this.checksum == 0) {
            bb.rewind();
            int accumulation = 0;

            for (int i = 0; i < length / 2; ++i) {
                accumulation += 0xffff & bb.getShort();
            }
            // pad to an even number of shorts
            if (length % 2 > 0) {
                accumulation += (bb.get() & 0xff) << 8;
            }

            accumulation = ((accumulation >> 16) & 0xffff)
                    + (accumulation & 0xffff);
            this.checksum = (short) (~accumulation & 0xffff);
            bb.putShort(2, this.checksum);
        }
        return data;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + checksum;
        result = prime * result + code;
        result = prime * result + Arrays.hashCode(data);
        result = prime * result + type;
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof ICMP))
            return false;
        ICMP other = (ICMP) obj;
        if (checksum != other.checksum)
            return false;
        if (code != other.code)
            return false;
        if (!Arrays.equals(data, other.data))
            return false;
        if (type != other.type)
            return false;
        return true;
    }

    @Override
    public IPacket deserialize(byte[] data, int offset, int length) {
        ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
        this.type = bb.get();
        this.code = bb.get();
        this.checksum = bb.getShort();
        if ((length - 4) > 0) {
            this.data = new byte[length-4];
            bb.get(this.data);
        }

        return this;
    }
}
