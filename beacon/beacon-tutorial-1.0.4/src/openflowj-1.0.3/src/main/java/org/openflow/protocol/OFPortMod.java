package org.openflow.protocol;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.openflow.util.U16;

/**
 * Represents an ofp_port_mod message
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFPortMod extends OFMessage {
    public static int MINIMUM_LENGTH = 32;

    protected short portNumber;
    protected byte[] hardwareAddress;
    protected int config;
    protected int mask;
    protected int advertise;

    public OFPortMod() {
        super();
        this.type = OFType.PORT_MOD;
        this.length = U16.t(MINIMUM_LENGTH);
    }

    /**
     * @return the portNumber
     */
    public short getPortNumber() {
        return portNumber;
    }

    /**
     * @param portNumber the portNumber to set
     */
    public OFPortMod setPortNumber(short portNumber) {
        this.portNumber = portNumber;
        return this;
    }

    /**
     * @return the hardwareAddress
     */
    public byte[] getHardwareAddress() {
        return hardwareAddress;
    }

    /**
     * @param hardwareAddress the hardwareAddress to set
     */
    public OFPortMod setHardwareAddress(byte[] hardwareAddress) {
        if (hardwareAddress.length != OFPhysicalPort.OFP_ETH_ALEN)
            throw new RuntimeException("Hardware address must have length "
                    + OFPhysicalPort.OFP_ETH_ALEN);
        this.hardwareAddress = hardwareAddress;
        return this;
    }

    /**
     * @return the config
     */
    public int getConfig() {
        return config;
    }

    /**
     * @param config the config to set
     */
    public OFPortMod setConfig(int config) {
        this.config = config;
        return this;
    }

    /**
     * @return the mask
     */
    public int getMask() {
        return mask;
    }

    /**
     * @param mask the mask to set
     */
    public OFPortMod setMask(int mask) {
        this.mask = mask;
        return this;
    }

    /**
     * @return the advertise
     */
    public int getAdvertise() {
        return advertise;
    }

    /**
     * @param advertise the advertise to set
     */
    public OFPortMod setAdvertise(int advertise) {
        this.advertise = advertise;
        return this;
    }

    @Override
    public void readFrom(ByteBuffer data) {
        super.readFrom(data);
        this.portNumber = data.getShort();
        if (this.hardwareAddress == null)
            this.hardwareAddress = new byte[OFPhysicalPort.OFP_ETH_ALEN];
        data.get(this.hardwareAddress);
        this.config = data.getInt();
        this.mask = data.getInt();
        this.advertise = data.getInt();
        data.getInt(); // pad
    }

    @Override
    public void writeTo(ByteBuffer data) {
        super.writeTo(data);
        data.putShort(this.portNumber);
        data.put(this.hardwareAddress);
        data.putInt(this.config);
        data.putInt(this.mask);
        data.putInt(this.advertise);
        data.putInt(0); // pad
    }

    @Override
    public int hashCode() {
        final int prime = 311;
        int result = super.hashCode();
        result = prime * result + advertise;
        result = prime * result + config;
        result = prime * result + Arrays.hashCode(hardwareAddress);
        result = prime * result + mask;
        result = prime * result + portNumber;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof OFPortMod)) {
            return false;
        }
        OFPortMod other = (OFPortMod) obj;
        if (advertise != other.advertise) {
            return false;
        }
        if (config != other.config) {
            return false;
        }
        if (!Arrays.equals(hardwareAddress, other.hardwareAddress)) {
            return false;
        }
        if (mask != other.mask) {
            return false;
        }
        if (portNumber != other.portNumber) {
            return false;
        }
        return true;
    }

    /* (non-Javadoc)
     * @see org.openflow.protocol.OFMessage#computeLength()
     */
    @Override
    public void computeLength() {
        this.length = (short) MINIMUM_LENGTH;
    }
}
