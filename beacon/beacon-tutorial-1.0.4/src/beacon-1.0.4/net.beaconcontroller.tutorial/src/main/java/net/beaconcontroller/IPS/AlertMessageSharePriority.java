/**
 * We use this class to share the same alert priority in the DDoS detection,
 * based on the source network address and the few number of packets on his
 * flows. Thus, when we detect the DoS attack we can automatically change the
 * priority for all flows related with this source address. This avoid one loop
 * for to do this.
 * 
 * Extend AlertMessage class, adding some attributes! 
 * 
 *  @author Luiz Arthur Feitosa dos Santos
 *  @email luiz.arthur.feitosa.santos@gmail.com
 * 
 */

package net.beaconcontroller.IPS;

public class AlertMessageSharePriority extends AlertMessage {
    
    private static int priorityAlert = Integer.MAX_VALUE;

    public int getPriorityAlert() {
        return priorityAlert;
    }

    public void setPriorityAlert(int priorityAlert) {
        AlertMessageSharePriority.priorityAlert = priorityAlert;
    }

}
