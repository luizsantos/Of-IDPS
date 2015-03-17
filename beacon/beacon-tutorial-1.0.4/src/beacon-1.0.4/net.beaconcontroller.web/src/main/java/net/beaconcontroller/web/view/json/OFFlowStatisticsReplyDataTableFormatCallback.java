/**
 * Copyright 2010-2013, Stanford University. This file is licensed under the
 * BSD license as described in the included LICENSE.txt.
 */
package net.beaconcontroller.web.view.json;

import java.io.IOException;

import net.beaconcontroller.packet.IPv4;
import net.beaconcontroller.web.view.json.DataTableJsonView.DataTableFormatCallback;

import org.apache.commons.lang3.StringEscapeUtils;
import org.codehaus.jackson.JsonGenerator;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.openflow.util.U32;
import org.openflow.util.U64;
import org.openflow.util.U8;

/**
 *
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFFlowStatisticsReplyDataTableFormatCallback implements
        DataTableFormatCallback<OFFlowStatisticsReply> {

    protected String switchId;

    public OFFlowStatisticsReplyDataTableFormatCallback(String switchId) {
        super();
        this.switchId = switchId;
    }

    @Override
    public void format(OFFlowStatisticsReply data, JsonGenerator jg) throws IOException {
        jg.writeNumber(U16.f(data.getMatch().getInputPort()));
        jg.writeString(HexString.toHexString(data.getMatch().getDataLayerSource()));
        jg.writeString(HexString.toHexString(data.getMatch().getDataLayerDestination()));
        jg.writeNumber(U16.f(data.getMatch().getDataLayerType()));
        jg.writeString(IPv4.fromIPv4Address(data.getMatch().getNetworkSource()));
        jg.writeString(IPv4.fromIPv4Address(data.getMatch().getNetworkDestination()));
        jg.writeNumber(U8.f(data.getMatch().getNetworkProtocol()));
        jg.writeNumber(U16.f(data.getMatch().getTransportSource()));
        jg.writeNumber(U16.f(data.getMatch().getTransportDestination()));
        jg.writeNumber(U32.f(data.getMatch().getWildcards()));
        jg.writeNumber(U64.f(data.getByteCount()));
        jg.writeNumber(U64.f(data.getPacketCount()));
        jg.writeNumber(((double) U32.f(data.getDurationSeconds()))
                + ((double) data.getDurationNanoseconds()) / 1000000000d);
        jg.writeNumber(U16.f(data.getIdleTimeout()));
        jg.writeNumber(U16.f(data.getHardTimeout()));
        jg.writeNumber(U64.f(data.getCookie()));
        StringBuffer outPorts = new StringBuffer();
        for (OFAction action : data.getActions()) {
            if (action instanceof OFActionOutput) {
                OFActionOutput ao = (OFActionOutput)action;
                if (outPorts.length() > 0)
                    outPorts.append(" ");
                outPorts.append(U16.f(ao.getPort()));
            }
        }
        jg.writeString(outPorts.toString());
        String url = StringEscapeUtils.escapeHtml3("/wm/core/switch/"+
                switchId+"/flow/"+data.getMatch().toString()+"/del");
        jg.writeString("<a href=\""+url+"\">del</a>");
    }
}
