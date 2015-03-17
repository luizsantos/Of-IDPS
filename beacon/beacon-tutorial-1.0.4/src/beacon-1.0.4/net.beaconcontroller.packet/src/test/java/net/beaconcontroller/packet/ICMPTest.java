/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

/**
 * @author David Erickson (daviderickson@cs.stanford.edu)
 *
 */
public class ICMPTest {
    public byte[] icmpRequest = new byte[] { (byte) 0x00, (byte) 0x50,
            (byte) 0x56, (byte) 0xfc, (byte) 0x8a, (byte) 0xb7, (byte) 0x00,
            (byte) 0x0c, (byte) 0x29, (byte) 0xea, (byte) 0x51, (byte) 0x0c,
            (byte) 0x08, (byte) 0x00, (byte) 0x45, (byte) 0x00, (byte) 0x00,
            (byte) 0x54, (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x00,
            (byte) 0x40, (byte) 0x01, (byte) 0x57, (byte) 0xf6, (byte) 0xc0,
            (byte) 0xa8, (byte) 0xce, (byte) 0x03, (byte) 0x4a, (byte) 0x35,
            (byte) 0x09, (byte) 0xd2, (byte) 0x08, (byte) 0x00, (byte) 0x77,
            (byte) 0xb3, (byte) 0xf6, (byte) 0x1c, (byte) 0x00, (byte) 0x03,
            (byte) 0xcc, (byte) 0xa8, (byte) 0x75, (byte) 0x50, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x7c, (byte) 0x60,
            (byte) 0x0d, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
            (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22,
            (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27,
            (byte) 0x28, (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c,
            (byte) 0x2d, (byte) 0x2e, (byte) 0x2f, (byte) 0x30, (byte) 0x31,
            (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
            (byte) 0x37 };

    public byte[] icmpReply = new byte[] { 0x00, 0x0c, 0x29, (byte) 0xea, 0x51,
            0x0c, 0x00, 0x50, 0x56, (byte) 0xfc, (byte) 0x8a, (byte) 0xb7,
            0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x5d, 0x00, 0x00,
            (byte) 0x80, 0x01, 0x57, (byte) 0x99, 0x4a, 0x35, 0x09,
            (byte) 0xd2, (byte) 0xc0, (byte) 0xa8, (byte) 0xce, 0x03, 0x00,
            0x00, 0x7f, (byte) 0xb3, (byte) 0xf6, 0x1c, 0x00, 0x03,
            (byte) 0xcc, (byte) 0xa8, 0x75, 0x50, 0x00, 0x00, 0x00, 0x00, 0x7c,
            0x60, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37 };

    @Test
    public void testICMPRequest() {
        Ethernet eth = new Ethernet();
        eth.deserialize(icmpRequest, 0, icmpRequest.length);
        assertTrue(eth.getPayload() instanceof IPv4);
        IPv4 ip = (IPv4) eth.getPayload();
        assertTrue(ip.getPayload() instanceof ICMP);
        ICMP icmp = (ICMP) ip.getPayload();
        assertEquals(icmp.getType(), 8);
        assertEquals(icmp.getCode(), 0);
        assertEquals(icmp.getChecksum(), 0x77b3);
        assertEquals(icmp.getData().length, 60);

        byte[] serialized = eth.serialize();
        for (int i = 0; i < serialized.length; ++i) {
            if (serialized[i] != icmpRequest[i])
                System.out.println(i);
        }
        assertTrue(Arrays.equals(icmpRequest, serialized));

        IPacket packet = new Ethernet()
            .setSourceMACAddress("00:0c:29:ea:51:0c")
            .setDestinationMACAddress("00:50:56:fc:8a:b7")
            .setPayload(new IPv4()
                .setDestinationAddress("74.53.9.210")
                .setFlags((byte) 0x2)
                .setSourceAddress("192.168.206.3")
                .setTtl((byte) 64)
                .setPayload(new ICMP()
                    .setType((byte) 8)
                    .setCode((byte) 0)
                    .setData(new byte [] {(byte) 0xf6, (byte) 0x1c, (byte) 0x00, (byte) 0x03,
                            (byte) 0xcc, (byte) 0xa8, (byte) 0x75, (byte) 0x50, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x7c, (byte) 0x60,
                            (byte) 0x0d, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
                            (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
                            (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22,
                            (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27,
                            (byte) 0x28, (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c,
                            (byte) 0x2d, (byte) 0x2e, (byte) 0x2f, (byte) 0x30, (byte) 0x31,
                            (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
                            (byte) 0x37})
                )
            );

        serialized = packet.serialize();
        assertEquals(eth, packet);
        assertTrue(Arrays.equals(icmpRequest, serialized));
    }

    @Test
    public void testICMPReply() {
        Ethernet eth = new Ethernet();
        eth.deserialize(icmpReply, 0, icmpReply.length);
        assertTrue(eth.getPayload() instanceof IPv4);
        IPv4 ip = (IPv4) eth.getPayload();
        assertTrue(ip.getPayload() instanceof ICMP);
        ICMP icmp = (ICMP) ip.getPayload();
        assertEquals(icmp.getType(), 0);
        assertEquals(icmp.getCode(), 0);
        assertEquals(icmp.getChecksum(), 0x7fb3);
        assertEquals(icmp.getData().length, 60);

        byte[] serialized = eth.serialize();
        assertTrue(Arrays.equals(icmpReply, serialized));

        IPacket packet = new Ethernet()
            .setSourceMACAddress("00:50:56:fc:8a:b7")
            .setDestinationMACAddress("00:0c:29:ea:51:0c")
            .setPayload(new IPv4()
                .setDestinationAddress("192.168.206.3")
                .setIdentification((short) 0x5d)
                .setSourceAddress("74.53.9.210")
                .setTtl((byte) 128)
                .setPayload(new ICMP()
                    .setType((byte) 0)
                    .setCode((byte) 0)
                    .setData(new byte [] { (byte) 0xf6, 0x1c, 0x00, 0x03,
                            (byte) 0xcc, (byte) 0xa8, 0x75, 0x50, 0x00, 0x00,
                            0x00, 0x00, 0x7c, 0x60, 0x0d, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                            0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                            0x36, 0x37 })
                )
            );

        serialized = packet.serialize();
        assertEquals(eth, packet);
        assertTrue(Arrays.equals(icmpReply, serialized));
    }
}
