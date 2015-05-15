/**
 * Represent OpenFlow statistics messages about switches flows.
 * 
 * This extend the OFFlowStatisticsReply class, adding some attributes.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 */
package net.beaconcontroller.DAO;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.json.simple.JSONObject;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatusFlow extends  OFFlowStatisticsReply {
    
    public final static int FLOW_NORMAL=0;
    public final static int FLOW_ABNORMAL=1;
    
    protected int flowId; // This field is auto increment!
    protected long swID;
    protected Date time;
    protected byte[] dataLayerDestination;
    protected byte[] dataLayerSource;
    protected short dataLayerType;
    protected short dataLayerVirtualLan;
    protected byte dataLayerVirtualLanPriorityCodePoint;
    protected short inputPort;
    protected int networkDestination;
    protected byte networkProtocol;
    protected int networkSource;
    protected byte networkTypeOfService;
    protected short transportDestination ;
    protected short transportSource;
    protected int wildcards;
    private int life=1; // If >=0 rule is alive in memory, if < 0 this must be write on database.
    private int flowType=FLOW_NORMAL;
    private boolean inSwitchesMemory = false; // if true is on switch memory, case false not!

    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    
    /**
     * 
     * Generate the key from the OpenFlow flow message, this can be used to
     * identify/differentiate the flows.
     * 
     * @return the key formed by switch ID, source hardware address, destination
     *         hardware address, type protocol hardware, source network address,
     *         destination network address, protocol network, source transport
     *         port, destination transport port.
     */
    public String getKey() {
        String hwdataLayerSource = new String(this.dataLayerSource);
        String hwdataLayerDestination = new String(this.dataLayerDestination);
        
        return Long.toString(swID)+
                hwdataLayerSource+
                hwdataLayerDestination+
                Integer.toString(this.dataLayerType)+
                Integer.toString(this.networkSource)+
                Integer.toString(this.networkDestination)+
                Integer.toString(this.networkProtocol)+
                Integer.toString(this.transportSource)+
                Integer.toString(this.transportDestination);
    }
    
    /**
     * Convert the value number of flowtype attribute into a string form.
     * 
     * @return "normal" or "abnormal" strings.
     */
    private String convertFlowTypeToString() {
        String stringFlowType = "";
        if (this.flowType==FLOW_NORMAL) {
            stringFlowType="NORMAL";
        } else {
            stringFlowType="ABNORMAL";
        }
        return stringFlowType;
    }
    
    /**
     * Print status flow
     */
    public void printStatusFlow(String text) {
        String hwdataLayerSource = HexString.toHexString(this.dataLayerSource);
        String hwdataLayerDestination = HexString.toHexString(this.dataLayerDestination);
        
        log.debug(text+": ["+hwdataLayerSource+"->"+hwdataLayerDestination+"{"+ this.dataLayerType+"}]"+
                this.networkSource+":"+this.transportSource+"->"+
                this.networkDestination+":"+this.transportDestination+" ("+
                this.networkProtocol+")"+" bytes: " +this.byteCount + " packets: " + this.packetCount +
                " live: "+ this.life +" - "+ this.getTimeString() +" type: "+ convertFlowTypeToString()+
                " inSwMemory: "+ this.inSwitchesMemory + "flowId"+ this.flowId);
    }
    
    
    public JSONObject getJSONStatusFlow() {
        JSONObject flowJSON = new JSONObject();
        String hwdataLayerSource = HexString.toHexString(this.dataLayerSource);
        flowJSON.put("dataLayerSource", hwdataLayerSource);
        String hwdataLayerDestination = HexString.toHexString(this.dataLayerDestination);
        flowJSON.put("dataLayerDestination", hwdataLayerDestination);
        flowJSON.put("dataLayerType", this.dataLayerType);
        flowJSON.put("networkSource", this.networkSource);
        flowJSON.put("networkDestination", this.networkDestination);
        flowJSON.put("networkProtocol", this.networkProtocol);
        flowJSON.put("transportSource", this.transportSource);
        flowJSON.put("transportDestination", this.transportDestination);
        flowJSON.put("byteCount", this.byteCount);
        flowJSON.put("packetCount", this.packetCount);
        flowJSON.put("life", this.life);
        flowJSON.put("time", this.getTimeString());
        flowJSON.put("flowType", convertFlowTypeToString());
        return flowJSON;
    }
    
    public int getFlowId() {
        return flowId;
    }
    public void setFlowId(int flowId) {
        this.flowId = flowId;
    }
    public byte[] getDataLayerDestination() {
        return dataLayerDestination;
    }
    public void setDataLayerDestination(byte[] dataLayerDestination) {
        this.dataLayerDestination = dataLayerDestination;
    }
    public byte[] getDataLayerSource() {
        return dataLayerSource;
    }
    public void setDataLayerSource(byte[] dataLayerSource) {
        this.dataLayerSource = dataLayerSource;
    }
    public short getDataLayerType() {
        return dataLayerType;
    }
    public void setDataLayerType(short dataLayerType) {
        this.dataLayerType = dataLayerType;
    }
    public short getDataLayerVirtualLan() {
        return dataLayerVirtualLan;
    }
    public void setDataLayerVirtualLan(short dataLayerVirtualLan) {
        this.dataLayerVirtualLan = dataLayerVirtualLan;
    }
    public byte getDataLayerVirtualLanPriorityCodePoint() {
        return dataLayerVirtualLanPriorityCodePoint;
    }
    public void setDataLayerVirtualLanPriorityCodePoint(
            byte dataLayerVirtualLanPriorityCodePoint) {
        this.dataLayerVirtualLanPriorityCodePoint = dataLayerVirtualLanPriorityCodePoint;
    }
    public short getInputPort() {
        return inputPort;
    }
    public void setInputPort(short inputPort) {
        this.inputPort = inputPort;
    }
    public int getNetworkDestination() {
        return networkDestination;
    }
    public void setNetworkDestination(int networkDestination) {
        this.networkDestination = networkDestination;
    }
    public byte getNetworkProtocol() {
        return networkProtocol;
    }
    public void setNetworkProtocol(byte networkProtocol) {
        this.networkProtocol = networkProtocol;
    }
    public int getNetworkSource() {
        return networkSource;
    }
    public void setNetworkSource(int networkSource) {
        this.networkSource = networkSource;
    }
    public byte getNetworkTypeOfService() {
        return networkTypeOfService;
    }
    public void setNetworkTypeOfService(byte networkTypeOfService) {
        this.networkTypeOfService = networkTypeOfService;
    }
    public short getTransportDestination() {
        return transportDestination;
    }
    public void setTransportDestination(short transportDestination) {
        this.transportDestination = transportDestination;
    }
    public short getTransportSource() {
        return transportSource;
    }
    public void setTransportSource(short transportSource) {
        this.transportSource = transportSource;
    }
    public int getWildcards() {
        return wildcards;
    }
    public void setWildcards(int wildcards) {
        this.wildcards = wildcards;
    }
    public long getSwID() {
        return swID;
    }
    public void setSwID(long swID) {
        this.swID = swID;
    }
    public Date getTime() {
        return time;
    }
    public void setTime(Date time) {
        this.time = time;
    }
    public int getFlowType() {
        return flowType;
    }
    public void setFlowType(int flowType) {
        this.flowType = flowType;
    }
    
    /**
     * This flow is on switch memory?
     * @return - True, if yes. False if not!
     */
    public boolean isInSwitchesMemory() {
        return inSwitchesMemory;
    }

    /**
     * This flow is on switch memory?
     * @param inSwitchesMemory - True, if the flow is on switch memory or false if not!
     */
    public void setInSwitchesMemory(boolean inSwitchesMemory) {
        this.inSwitchesMemory = inSwitchesMemory;
    }
    
    /**
     * Convert a string to date, the string must be passed in format:
     *              yyyy/MM/dd-HH:mm:ss.SSS
     * where: 
     *  yyyy - year
     *  MM - month
     *  dd - day
     *  HH - hour
     *  mm - minutes
     *  ss - seconds
     *  SSS - milliseconds
     * 
     * @param time - yyyy/MM/dd-HH:mm:ss.SSS
     */
    public void setTime(String datetime) {
        this.time = DateTimeManager.stringDatetoJavaDate(datetime);
    }
    
    /**
     * Convert a string to date, the string must be passed in format:
     *              yyyy-MM-dd-HH mm:ss.SSS
     * where: 
     *  yyyy - year
     *  MM - month
     *  dd - day
     *  HH - hour
     *  mm - minutes
     *  ss - seconds
     *  SSS - milliseconds
     * 
     * @param time - yyyy-MM-dd HH:mm:ss.SSS
     */
    public void setTimeFromDB(String datetime) {
            this.time = DateTimeManager.stringDateDBtoJavaDate(datetime); 
    }
    
    public String getTimeString() { 
        return DateTimeManager.dateToStringJavaDate(this.time);
    }
    
    public String getTimeStringBD() {
        return DateTimeManager.dateToStringDBDate(this.time);
    }
    
    /**
     * verify if Status Message have our time expired.
     * 
     *  @return true = expired and false not expired.
     */
    public boolean verifyIfStatusMessageHaveTimeExpired() {
        Calendar currentDateTime = Calendar.getInstance();
        /*
         * We use a margin of 6 seconds to avoid remove status.
         * Normally, flows idle are removed in 5 seconds.
         */
        currentDateTime.add(Calendar.MILLISECOND, -6000);
        if(this.time.after(currentDateTime.getTime())) {
            // flow time it's valid
//            log.debug("time flow NOT expired");
//            log.debug("{} <{}> {}",formatter.format(currentDateTime.getTime()), formatter.format(this.time), formatter.format(new Date()));
            //this.printStatusFlow();
            return false;
        } else {
            // this flow have your time expired
//            log.debug("time flow expired");
//            log.debug("<{}> {} {}",formatter.format(this.time), formatter.format(currentDateTime.getTime()), formatter.format(new Date()));
            //this.printStatusFlow();
            return true;
        }
    }

    /**
     * Set all StatusPort attributes.
     * 
     * @param switchId - Switch Id.
     * @param timeOfMessage - Represent the datetime that this message was collected from switch.
     * @param status - Represents the OFPortStaticsReply original, and we will use this to set the rest of StatusPort attributes.
     */
    public void setAllAttributesOfStatusFlow(long switchId, Date timeOfMessage, OFFlowStatisticsReply status){
        this.setSwID(switchId);
        this.setTime(timeOfMessage);
        
        // actionFactory - There are this attribute in the OFFlowStatisticsReply but we don't use this here! 
        // actions - There are this attribute in the OFFlowStatisticsReply but we don't use this here!
        this.setByteCount(status.getByteCount());
        this.setCookie(status.getCookie());
        this.setDurationNanoseconds(status.getDurationNanoseconds());
        this.setDurationSeconds(status.getDurationSeconds());
        this.setHardTimeout(status.getHardTimeout());
        this.setIdleTimeout(status.getIdleTimeout());
        this.setLength((short) status.getLength());
        this.setMatch(status.getMatch());
        this.setPacketCount(status.getPacketCount());
        this.setPriority(status.getPriority());
        this.setTableId(status.getTableId());
        
        OFMatch m = new OFMatch();
        m = status.getMatch();
        
        this.setDataLayerDestination(m.getDataLayerDestination());
        this.setDataLayerSource(m.getDataLayerSource());
        this.setDataLayerType(m.getDataLayerType());
        this.setDataLayerVirtualLan(m.getDataLayerVirtualLan());
        this.setDataLayerVirtualLanPriorityCodePoint(m.getDataLayerVirtualLanPriorityCodePoint());
        this.setInputPort(m.getInputPort());
        this.setNetworkDestination(m.getNetworkDestination());
        this.setNetworkProtocol(m.getNetworkProtocol());
        this.setNetworkSource(m.getNetworkSource());
        this.setNetworkTypeOfService(m.getNetworkTypeOfService());
        this.setTransportDestination(m.getTransportDestination());
        this.setTransportSource(m.getTransportSource());
        this.setWildcards(m.getWildcards());
        
    }
    
    public boolean isAlive() {
        if(this.life<0){
            return false; // dead record on database.
        } else {
            return true; // is alive keep on memory.
        }
    }

    public void keepAlive( ) {
        this.life = 1;
    }
    
    public void decreaseLife( ) {
        this.life--;
    }
    
    public void setLiveAsDead() {
        this.life=-2; // this will be used to show that this status come from database!
    }
//    public void setLife(int x) {
//        this.life = x;
//    }
}
