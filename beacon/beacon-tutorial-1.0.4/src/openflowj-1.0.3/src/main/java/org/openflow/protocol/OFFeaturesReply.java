package org.openflow.protocol;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.openflow.util.U16;


/**
 * Represents a features reply message
 * @author David Erickson (daviderickson@cs.stanford.edu)
 *
 */
public class OFFeaturesReply extends OFMessage {
    public static int MINIMUM_LENGTH = 32;

    /**
     * Corresponds to bits on the capabilities field
     */
    public enum OFCapabilities {
        OFPC_FLOW_STATS     (1 << 0),
        OFPC_TABLE_STATS    (1 << 1),
        OFPC_PORT_STATS     (1 << 2),
        OFPC_STP            (1 << 3),
        OFPC_RESERVED       (1 << 4),
        OFPC_IP_REASM       (1 << 5),
        OFPC_QUEUE_STATS    (1 << 6),
        OFPC_ARP_MATCH_IP   (1 << 7);

        protected int value;

        private OFCapabilities(int value) {
            this.value = value;
        }

        /**
         * @return the value
         */
        public int getValue() {
            return value;
        }
    }

    protected long datapathId;
    protected int buffers;
    protected byte tables;
    protected int capabilities;
    protected int actions;
    protected List<OFPhysicalPort> ports;

    public OFFeaturesReply() {
        super();
        this.type = OFType.FEATURES_REPLY;
        this.length = U16.t(MINIMUM_LENGTH);
    }

    /**
     * @return the datapathId
     */
    public long getDatapathId() {
        return datapathId;
    }

    /**
     * @param datapathId the datapathId to set
     */
    public OFFeaturesReply setDatapathId(long datapathId) {
        this.datapathId = datapathId;
        return this;
    }

    /**
     * @return the buffers
     */
    public int getBuffers() {
        return buffers;
    }

    /**
     * @param buffers the buffers to set
     */
    public OFFeaturesReply setBuffers(int buffers) {
        this.buffers = buffers;
        return this;
    }

    /**
     * @return the tables
     */
    public byte getTables() {
        return tables;
    }

    /**
     * @param tables the tables to set
     */
    public OFFeaturesReply setTables(byte tables) {
        this.tables = tables;
        return this;
    }

    /**
     * @return the capabilities
     */
    public int getCapabilities() {
        return capabilities;
    }

    /**
     * @param capabilities the capabilities to set
     */
    public OFFeaturesReply setCapabilities(int capabilities) {
        this.capabilities = capabilities;
        return this;
    }

    /**
     * @return the actions
     */
    public int getActions() {
        return actions;
    }

    /**
     * @param actions the actions to set
     */
    public OFFeaturesReply setActions(int actions) {
        this.actions = actions;
        return this;
    }

    /**
     * @return the ports
     */
    public List<OFPhysicalPort> getPorts() {
        return ports;
    }

    /**
     * Returns a map of port number to OFPhysicalPort object
     * @return
     */
    public Map<Short, OFPhysicalPort> getPortMap() {
        Map<Short, OFPhysicalPort> map = new HashMap<Short, OFPhysicalPort>();
        if (this.ports != null) {
            for (OFPhysicalPort port : this.ports) {
                map.put(port.getPortNumber(), port);
            }
        }
        return map;
    }

    /**
     * @param ports the ports to set
     */
    public OFFeaturesReply setPorts(List<OFPhysicalPort> ports) {
        this.ports = ports;
        if (ports == null) {
            this.setLengthU(MINIMUM_LENGTH);
        } else {
            this.setLengthU(MINIMUM_LENGTH + ports.size()
                    * OFPhysicalPort.MINIMUM_LENGTH);
        }
        return this;
    }

    @Override
    public void readFrom(ByteBuffer data) {
        super.readFrom(data);
        this.datapathId = data.getLong();
        this.buffers = data.getInt();
        this.tables = data.get();
        data.position(data.position() + 3); // pad
        this.capabilities = data.getInt();
        this.actions = data.getInt();
        if (this.ports == null) {
            this.ports = new ArrayList<OFPhysicalPort>();
        } else {
            this.ports.clear();
        }
        int portCount = (super.getLengthU() - 32)
                / OFPhysicalPort.MINIMUM_LENGTH;
        OFPhysicalPort port;
        for (int i = 0; i < portCount; ++i) {
            port = new OFPhysicalPort();
            port.readFrom(data);
            this.ports.add(port);
        }
    }

    @Override
    public void writeTo(ByteBuffer data) {
        super.writeTo(data);
        data.putLong(this.datapathId);
        data.putInt(this.buffers);
        data.put(this.tables);
        data.putShort((short) 0); // pad
        data.put((byte) 0); // pad
        data.putInt(this.capabilities);
        data.putInt(this.actions);
        if (this.ports != null)
            for (OFPhysicalPort port : this.ports) {
                port.writeTo(data);
            }
    }

    @Override
    public int hashCode() {
        final int prime = 139;
        int result = super.hashCode();
        result = prime * result + actions;
        result = prime * result + buffers;
        result = prime * result + capabilities;
        result = prime * result + (int) (datapathId ^ (datapathId >>> 32));
        result = prime * result + ((ports == null) ? 0 : ports.hashCode());
        result = prime * result + tables;
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
        if (!(obj instanceof OFFeaturesReply)) {
            return false;
        }
        OFFeaturesReply other = (OFFeaturesReply) obj;
        if (actions != other.actions) {
            return false;
        }
        if (buffers != other.buffers) {
            return false;
        }
        if (capabilities != other.capabilities) {
            return false;
        }
        if (datapathId != other.datapathId) {
            return false;
        }
        if (ports == null) {
            if (other.ports != null) {
                return false;
            }
        } else if (!ports.equals(other.ports)) {
            return false;
        }
        if (tables != other.tables) {
            return false;
        }
        return true;
    }

    /* (non-Javadoc)
     * @see org.openflow.protocol.OFMessage#computeLength()
     */
    @Override
    public void computeLength() {
        this.length = U16.t(MINIMUM_LENGTH + ((ports != null) ? (ports.size() * OFPhysicalPort.MINIMUM_LENGTH) : 0));
    }
}
