/**
 * Represent OpenFlow statistics messages about switches ports.
 * 
 * This extend the OFPortStatisticsReply class, adding the switch id and datetime attribute.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 */
package net.beaconcontroller.DAO;

import org.openflow.protocol.statistics.OFPortStatisticsReply;

public class StatusPort extends OFPortStatisticsReply {
    protected long swID; // Number that represent and identify the switch.
    protected long tempo; // Time that this message arrived.
    
    
    public long getSwID() {
        return swID;
    }
    
    /**
     * @param swID 
     */
    public void setSwID(long swID) {
        this.swID = swID;
    }
    
    /**
     * Get time.
     * 
     * @return - Time that message arrived on the system.
     */
    public long getTempo() {
        return tempo;
    }
    /**
     * Set time.
     * 
     * @param tempo - Time that message arrived.
     */
    public void setTempo(long tempo) {
        this.tempo = tempo;
    }
        
    /**
     * Set all StatusPort attributes.
     * 
     * @param iDdoSWitch - Switch Id.
     * @param timeOfMessage - Represent the datetime that this message was collected from switch.
     * @param status - Represents the OFPortStaticsReply original, and we will use this to set the rest of StatusPort attributes.
     * 
     */
    public void setAllAttributesOfStatusPort(long switchId, long timeOfMessage, OFPortStatisticsReply status){
        this.setSwID(switchId);
        this.setTempo(timeOfMessage);
        this.setCollisions(status.getCollisions());
        this.setPortNumber(status.getPortNumber());
        this.setReceiveBytes(status.getReceiveBytes());
        this.setReceiveCRCErrors(status.getReceiveCRCErrors());
        this.setReceiveDropped(status.getReceiveDropped());
        this.setreceiveErrors(status.getreceiveErrors());
        this.setReceiveFrameErrors(status.getReceiveFrameErrors());
        this.setReceiveOverrunErrors(status.getReceiveOverrunErrors());
        this.setreceivePackets(status.getreceivePackets());
        this.setTransmitBytes(status.getTransmitBytes());
        this.setTransmitDropped(status.getTransmitDropped());
        this.setTransmitErrors(status.getTransmitErrors());
        this.setTransmitPackets(status.getTransmitPackets());
    }
}
