/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.logging.bridge;

import org.osgi.service.log.LogEntry;
import org.osgi.service.log.LogListener;
import org.osgi.service.log.LogService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class SLF4JLogListener implements LogListener {
    private static Logger log = LoggerFactory.getLogger(SLF4JLogListener.class);

    public void logged(LogEntry entry) {
        switch (entry.getLevel()) {
            case LogService.LOG_DEBUG:
                log.debug(entry.getMessage(), entry.getException());
                break;
            case LogService.LOG_ERROR:
                log.error(entry.getMessage(), entry.getException());
                break;
            case LogService.LOG_INFO:
                log.info(entry.getMessage(), entry.getException());
                break;
            case LogService.LOG_WARNING:
                log.warn(entry.getMessage(), entry.getException());
                break;
        }
    }
}
