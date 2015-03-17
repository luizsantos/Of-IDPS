/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.packet;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class Ethernet extends BasePacket {
    private static String HEXES = "0123456789ABCDEF";
    public static short TYPE_ARP = 0x0806;
    public static short TYPE_IPv4 = 0x0800;
    public static short TYPE_LLDP = (short) 0x88cc;
    public static Map<Short, Class<? extends IPacket>> etherTypeClassMap;

    static {
        etherTypeClassMap = new HashMap<Short, Class<? extends IPacket>>();
        etherTypeClassMap.put(TYPE_ARP, ARP.class);
        etherTypeClassMap.put(TYPE_IPv4, IPv4.class);
        etherTypeClassMap.put(TYPE_LLDP, LLDP.class);
    }

    protected byte[] destinationMACAddress;
    protected byte[] sourceMACAddress;
    protected short etherType;
    protected boolean pad = false;

    /**
     *
     */
    public Ethernet() {
        super();
    }

    /**
     * Creates a new Ethernet instance and deserializes the data in the
     * provided packet.
     * @param packet the packet to deserialize
     */
    public Ethernet(byte[] packet) {
        super();
        deserialize(packet, 0, packet.length);
    }

    /**
     * Creates a new Ethernet instance and deserializes the data in the
     * provided packet.
     * @param packet the packet to deserialize
     * @param offset the offset within packet to begin deserialization
     * @param length the length of the packet to deserialize
     */
    public Ethernet(byte[] packet, int offset, int length) {
        super();
        deserialize(packet, offset, length);
    }

    /**
     * @return the destinationMACAddress
     */
    public byte[] getDestinationMACAddress() {
        return destinationMACAddress;
    }

    /**
     * @param destinationMACAddress the destinationMACAddress to set
     */
    public Ethernet setDestinationMACAddress(byte[] destinationMACAddress) {
        this.destinationMACAddress = destinationMACAddress;
        return this;
    }

    /**
     * @param destinationMACAddress the destinationMACAddress to set
     */
    public Ethernet setDestinationMACAddress(String destinationMACAddress) {
        this.destinationMACAddress = Ethernet
                .toMACAddress(destinationMACAddress);
        return this;
    }

    /**
     * @param destinationMACAddress the destinationMACAddress to set contained
     *      in the lower 6 bytes of the long
     */
    public Ethernet setDestinationMACAddress(long destinationMACAddress) {
        this.destinationMACAddress = Ethernet
                .toMACAddress(destinationMACAddress);
        return this;
    }

    /**
     * @return the sourceMACAddress
     */
    public byte[] getSourceMACAddress() {
        return sourceMACAddress;
    }

    /**
     * @param sourceMACAddress the sourceMACAddress to set
     */
    public Ethernet setSourceMACAddress(byte[] sourceMACAddress) {
        this.sourceMACAddress = sourceMACAddress;
        return this;
    }

    /**
     * @param sourceMACAddress the sourceMACAddress to set
     */
    public Ethernet setSourceMACAddress(String sourceMACAddress) {
        this.sourceMACAddress = Ethernet.toMACAddress(sourceMACAddress);
        return this;
    }

    /**
     * @return the etherType
     */
    public short getEtherType() {
        return etherType;
    }

    /**
     * @param etherType the etherType to set
     */
    public Ethernet setEtherType(short etherType) {
        this.etherType = etherType;
        return this;
    }

    /**
     * Pad this packet to 60 bytes minimum, filling with zeros?
     * @return the pad
     */
    public boolean isPad() {
        return pad;
    }

    /**
     * Pad this packet to 60 bytes minimum, filling with zeros?
     * @param pad the pad to set
     */
    public Ethernet setPad(boolean pad) {
        this.pad = pad;
        return this;
    }

    public byte[] serialize() {
        byte[] payloadData = null;
        if (payload != null) {
            payload.setParent(this);
            payloadData = payload.serialize();
        }
        int length = 14 + ((payloadData == null) ? 0 : payloadData.length);
        if (pad && length < 60) {
            length = 60;
        }
        byte[] data = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put(destinationMACAddress);
        bb.put(sourceMACAddress);
        bb.putShort(etherType);
        if (payloadData != null)
            bb.put(payloadData);
        if (pad) {
            Arrays.fill(data, bb.position(), data.length, (byte)0x0);
        }
        return data;
    }

    @Override
    public IPacket deserialize(byte[] data, int offset, int length) {
        ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
        if (this.destinationMACAddress == null)
            this.destinationMACAddress = new byte[6];
        bb.get(this.destinationMACAddress);

        if (this.sourceMACAddress == null)
            this.sourceMACAddress = new byte[6];
        bb.get(this.sourceMACAddress);
        this.etherType = bb.getShort();

        IPacket payload;
        if (Ethernet.etherTypeClassMap.containsKey(this.etherType)) {
            Class<? extends IPacket> clazz = Ethernet.etherTypeClassMap.get(this.etherType);
            try {
                payload = clazz.newInstance();
            } catch (Exception e) {
                throw new RuntimeException("Error parsing payload for Ethernet packet", e);
            }
        } else {
            payload = new Data();
        }
        this.payload = payload.deserialize(data, bb.position(), bb.limit()-bb.position());
        this.payload.setParent(this);
        return this;
    }

    /**
     * Accepts a MAC address of the form 00:aa:11:bb:22:cc, case does not
     * matter, and returns a corresponding byte[].
     * @param macAddress
     * @return
     */
    public static byte[] toMACAddress(String macAddress) {
        byte[] address = new byte[6];
        String[] macBytes = macAddress.split(":");
        if (macBytes.length != 6)
            throw new IllegalArgumentException(
                    "Specified MAC Address must contain 12 hex digits" +
                    " separated pairwise by :'s.");
        for (int i = 0; i < 6; ++i) {
            address[i] = (byte) ((HEXES.indexOf(macBytes[i].toUpperCase()
                    .charAt(0)) << 4) | HEXES.indexOf(macBytes[i].toUpperCase()
                    .charAt(1)));
        }

        return address;
    }

    /**
     * Converts a MAC address contained in the lower 6 bytes of the supplied
     * macAddress variable to a byte[]
     * @param macAddress The MAC address, contained in the lower 6 bytes.
     * @return the MAC address in a byte[]
     */
    public static byte[] toMACAddress(Long macAddress) {
        byte[] addr = new byte[6];
        long mac = macAddress;
        for (int i = 5; i >= 0; --i) {
            addr[i] = (byte)(mac & 0xff);
            mac >>= 8;
        }
        return addr;
    }

    /**
     * Accepts a MAC address and returns the corresponding long, where the
     * MAC bytes are set on the lower order bytes of the long.
     * @param macAddress
     * @return a long containing the mac address bytes
     */
    public static long toLong(byte[] macAddress) {
        long mac = 0;
        for (int i = 0; i < 6; i++) {
          long t = (macAddress[i] & 0xffL) << ((5-i)*8);
          mac |= t;
        }
        return mac;
    }

    /**
     * Accepts a MAC address of the form 00:aa:11:bb:22:cc, case does not
     * matter, and returns the corresponding long, where the MAC bytes are set
     * on the lower order bytes of the long.
     *
     * @param macAddress
     *            in String format
     * @return a long containing the mac address bytes
     */
    public static long toLong(String macAddress) {
        return toLong(toMACAddress(macAddress));
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 7867;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(destinationMACAddress);
        result = prime * result + etherType;
        result = prime * result + (pad ? 1231 : 1237);
        result = prime * result + Arrays.hashCode(sourceMACAddress);
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
        if (!(obj instanceof Ethernet))
            return false;
        Ethernet other = (Ethernet) obj;
        if (!Arrays.equals(destinationMACAddress, other.destinationMACAddress))
            return false;
        if (etherType != other.etherType)
            return false;
        if (pad != other.pad)
            return false;
        if (!Arrays.equals(sourceMACAddress, other.sourceMACAddress))
            return false;
        return true;
    }

    /**
     * Convenience method to check if the payload of this header is IPv4
     * @return true if the payload is IPv4, false otherwise
     */
    public boolean payloadIsIPv4() {
        return this.etherType == TYPE_IPv4;
    }

    /**
     * Convenience method to check if the payload of this header is ARP
     * @return true if the payload is ARP, false otherwise
     */
    public boolean payloadIsARP() {
        return this.etherType == TYPE_ARP;
    }

    /**
     * Convenience method to check if the payload of this header is LLDP
     * @return true if the payload is LLDP, false otherwise
     */
    public boolean payloadIsLLDP() {
        return this.etherType == TYPE_LLDP;
    }
}
