<%@page import="org.openflow.protocol.statistics.OFFlowStatisticsReply"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="org.openflow.util.*, org.openflow.protocol.*,
                 org.openflow.protocol.action.*, net.beaconcontroller.packet.*"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://www.beaconcontroller.net/tld/utils.tld" prefix="u" %>
  
<div class="section">
  <div class="section-header">${title}</div>
  <div class="section-content">
    <table id="table-flows-${switchIdEsc}" class="tableSection">
      <thead>
        <tr>
          <th>IP Src</th>
          <th>IP Dst</th>
          <th>IP Protot</th>
          <th>Src Port</th>
          <th>Dst Port</th>
          <th>Priority</th>
          <th>Description</th>
        </tr>
      </thead>
    </table>
  </div>
</div>

<script type="text/javascript" charset="utf-8">
    (function() {
        new DataTableWrapper('/wm/core/ofidps/alerts',
            {
              "bFilter": true
            }); 
    })();
</script>
