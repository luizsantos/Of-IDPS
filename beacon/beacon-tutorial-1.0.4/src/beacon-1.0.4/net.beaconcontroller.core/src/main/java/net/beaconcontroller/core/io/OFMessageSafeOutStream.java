/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core.io;

import org.openflow.io.OFMessageOutStream;

/**
 * This is a thread-safe implementation of the OFMessageOutStream
 * @author David Erickson (daviderickson@cs.stanford.edu)
 *
 */
public interface OFMessageSafeOutStream extends OFMessageOutStream {
}
