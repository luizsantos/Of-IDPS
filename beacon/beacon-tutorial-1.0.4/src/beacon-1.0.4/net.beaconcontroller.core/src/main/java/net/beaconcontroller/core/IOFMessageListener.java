/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.core;

import java.io.IOException;

import org.openflow.protocol.OFMessage;

/**
 *
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public interface IOFMessageListener {
    public enum Command {
        CONTINUE, STOP
    }

  /**
   * This is the method Beacon uses to call listeners with OpenFlow messages
   * @param sw the OpenFlow switch that sent this message
   * @param msg the message
   * @throws IOException
   * @return the command to continue or stop the execution
   */
  public Command receive(IOFSwitch sw, OFMessage msg) throws IOException;

  /**
   * The name assigned to this listener
   * @return
   */
  public String getName();
}
