package org.openflow.protocol;

import java.util.Collections;

import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.util.U16;

/**
 * Represents an ofp_stats_request message
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFStatisticsRequest extends OFStatisticsMessageBase {
    public OFStatisticsRequest() {
        super();
        this.type = OFType.STATS_REQUEST;
        this.length = U16.t(OFStatisticsMessageBase.MINIMUM_LENGTH);
    }

    /**
     * @return the statistics
     */
    public OFStatistics getStatistics() {
        if (statistics == null)
            return null;
        else if (statistics.size() == 0)
            return null;
        else
            return statistics.get(0);
    }

    /**
     * @param statistics the statistics to set
     */
    public OFStatisticsRequest setStatistics(OFStatistics statistics) {
        this.statistics = Collections.singletonList(statistics);
        return this;
    }
}
