package net.beaconcontroller.mactracker;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFMessageListener;
import net.beaconcontroller.core.IOFSwitch;

public class CopyOfMACTracker implements IOFMessageListener {
    protected static Logger logger = LoggerFactory.getLogger(CopyOfMACTracker.class);
    protected IBeaconProvider beaconProvider;
    protected Set<Integer> macAddresses = new ConcurrentSkipListSet<Integer>();;
    
    public IBeaconProvider getBeaconProvider() {
        return beaconProvider;
    }
    
    public void setBeaconProvider(IBeaconProvider beaconProvider) {
        this.beaconProvider = beaconProvider;
    }
    
    public void startUp(){
        //logger.info("-->Inicio mactracker");
        beaconProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
    
    public void shutDown() {
     beaconProvider.removeOFMessageListener(OFType.PACKET_IN, this);   
    }
    
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg) throws IOException {
        OFPacketIn pi = (OFPacketIn) msg;
        OFMatch match =  new OFMatch();
        match.loadFromPacket(pi.getPacketData(), (short) 0);
        Integer sourceMACHash = Arrays.hashCode(match.getDataLayerSource());
        
        
        //logger.info("-->Mac Address: {}", HexString.toHexString(match.getDataLayerSource()));
        //if(!HexString.toHexString(match.getDataLayerSource()).equals("00:00:00:00:00:01")) {
            //logger.info("-->Mac Address: {}", HexString.toHexString(match.getDataLayerSource()));
        
        
        if (!macAddresses.contains(sourceMACHash)) {
            macAddresses.add(sourceMACHash);
            //logger.info("Mac Address: {} seen on switch: {}", HexString.toHexString(match.getDataLayerSource()), sw.getId());
           
        }
        //}
        return Command.CONTINUE;
    }

    @Override
    public String getName() {
        return "mactracker";
        // TODO Auto-generated method stub
        //return null;
    }

}
