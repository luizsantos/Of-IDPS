package org.openflow.protocol;

import java.nio.ByteBuffer;
import java.util.List;

import org.openflow.protocol.factory.OFStatisticsFactory;
import org.openflow.protocol.factory.OFStatisticsFactoryAware;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.U16;


/**
 * Base class for statistics requests/replies
 *
 * @author David Erickson (daviderickson@cs.stanford.edu) - Mar 27, 2010
 */
public abstract class OFStatisticsMessageBase extends OFMessage implements
        OFStatisticsFactoryAware {
    public static int MINIMUM_LENGTH = 12;

    protected OFStatisticsFactory statisticsFactory;
    protected OFStatisticsType statisticType;
    protected short flags;
    protected List<OFStatistics> statistics;

    /**
     * @return the statisticType
     */
    public OFStatisticsType getStatisticType() {
        return statisticType;
    }

    /**
     * @param statisticType the statisticType to set
     */
    public OFStatisticsMessageBase setStatisticType(OFStatisticsType statisticType) {
        this.statisticType = statisticType;
        return this;
    }

    /**
     * @return the flags
     */
    public short getFlags() {
        return flags;
    }

    /**
     * @param flags the flags to set
     */
    public OFStatisticsMessageBase setFlags(short flags) {
        this.flags = flags;
        return this;
    }

    @Override
    public void setStatisticsFactory(OFStatisticsFactory statisticsFactory) {
        this.statisticsFactory = statisticsFactory;
    }

    @Override
    public void readFrom(ByteBuffer data) {
        super.readFrom(data);
        this.statisticType = OFStatisticsType.valueOf(data.getShort(), this
                .getType());
        this.flags = data.getShort();
        if (this.statisticsFactory == null)
            throw new RuntimeException("OFStatisticsFactory not set");
        this.statistics = statisticsFactory.parseStatistics(this.getType(),
                this.statisticType, data, super.getLengthU() - MINIMUM_LENGTH);
    }

    @Override
    public void writeTo(ByteBuffer data) {
        super.writeTo(data);
        data.putShort(this.statisticType.getTypeValue());
        data.putShort(this.flags);
        if (this.statistics != null) {
            for (OFStatistics statistic : this.statistics) {
                statistic.writeTo(data);
            }
        }
    }

    @Override
    public int hashCode() {
        final int prime = 317;
        int result = super.hashCode();
        result = prime * result + flags;
        result = prime * result
                + ((statisticType == null) ? 0 : statisticType.hashCode());
        result = prime * result
                + ((statistics == null) ? 0 : statistics.hashCode());
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
        if (!(obj instanceof OFStatisticsMessageBase)) {
            return false;
        }
        OFStatisticsMessageBase other = (OFStatisticsMessageBase) obj;
        if (flags != other.flags) {
            return false;
        }
        if (statisticType == null) {
            if (other.statisticType != null) {
                return false;
            }
        } else if (!statisticType.equals(other.statisticType)) {
            return false;
        }
        if (statistics == null) {
            if (other.statistics != null) {
                return false;
            }
        } else if (!statistics.equals(other.statistics)) {
            return false;
        }
        return true;
    }

    /* (non-Javadoc)
     * @see org.openflow.protocol.OFMessage#computeLength()
     */
    @Override
    public void computeLength() {
        int l = MINIMUM_LENGTH;
        if (statistics != null) {
            for (OFStatistics stat : statistics) {
                l += stat.computeLength();
            }
        }
        this.length = U16.t(l);
    }
}
