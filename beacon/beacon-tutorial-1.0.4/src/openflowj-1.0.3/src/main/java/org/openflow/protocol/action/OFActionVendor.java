package org.openflow.protocol.action;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 * @author James Hongyi Zeng (hyzeng@stanford.edu)
 */
public class OFActionVendor extends OFAction {
    public static int MINIMUM_LENGTH = 8;

    protected int vendor;
    protected byte[] data;

    public OFActionVendor() {
        super();
        super.setType(OFActionType.VENDOR);
        super.setLength((short) MINIMUM_LENGTH);
    }

    /**
     * @return the vendor
     */
    public int getVendor() {
        return vendor;
    }

    /**
     * @param vendor the vendor to set
     */
    public OFActionVendor setVendor(int vendor) {
        this.vendor = vendor;
        return this;
    }

    @Override
    public void readFrom(ByteBuffer data) {
        super.readFrom(data);
        this.vendor = data.getInt();
        int dataLength = this.length - MINIMUM_LENGTH;
        this.data = new byte[dataLength];
        data.get(this.data, 0, dataLength);
    }

    @Override
    public void writeTo(ByteBuffer data) {
        super.writeTo(data);
        data.putInt(this.vendor);
        data.put(this.data);
    }

    @Override
    public int hashCode() {
        final int prime = 379;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(data);
        result = prime * result + vendor;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof OFActionVendor))
            return false;
        OFActionVendor other = (OFActionVendor) obj;
        if (!Arrays.equals(data, other.data))
            return false;
        if (vendor != other.vendor)
            return false;
        return true;
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
    public void setData(byte[] data) {
        this.data = data;
    }
}
