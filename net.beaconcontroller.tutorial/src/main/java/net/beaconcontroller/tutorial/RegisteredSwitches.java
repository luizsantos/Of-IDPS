/**
 * 
 * Store all switches registered in the Of-IDPS controller, 
 * thus we don't need send OpenFlow messages to the network 
 * to discovery this switches and avoiding overhead.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 * TODO - I stopped that implement this class because I don't know 
 * if the old method used to discover switches on the network really 
 * send OpenFlow messages to the network to discover this! If send we 
 * can use this class to avoid overhead, but if not we can keep using 
 * the old method (getAllSwitchesOnNetwork)!
 */
package net.beaconcontroller.tutorial;

import java.util.concurrent.CopyOnWriteArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.beaconcontroller.core.IBeaconProvider;
import net.beaconcontroller.core.IOFSwitch;

public class RegisteredSwitches {
    
    protected IBeaconProvider beaconProvider;
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    /*
     * Verify if is necessary to control duplicate switches and 
     * switches that are disconnected but yet still on the list 
     * or registered switches! 
     */
    private static CopyOnWriteArrayList<IOFSwitch> listOfSwitchesRegistered = new CopyOnWriteArrayList<IOFSwitch>();

    public RegisteredSwitches(IBeaconProvider beaconProvider) {
        this.beaconProvider = beaconProvider;
    }

    public static CopyOnWriteArrayList<IOFSwitch> getSwitches() {
        return listOfSwitchesRegistered;
    }

    public static void setSwitches(CopyOnWriteArrayList<IOFSwitch> switches) {
        RegisteredSwitches.listOfSwitchesRegistered = switches;
    }
    
    /**
     * Print all switches registered on the Of-IDPS controller!
     */
    public void printRegisteredSwitches() {
        log.debug("List of all switches registered on Of-IDPS controller:");
        for(IOFSwitch sw: listOfSwitchesRegistered) {
            log.debug("Switch id: {}", sw.getId());
        }
    }
    
    /**
     * Add a switch to the registered switches list .
     * @param sw - Switch.
     * 
     * TODO - we can have duplicated switches, if we don't have an correct
     * disconnection of switches! Handle this problem.
     * 
     */
    public void addSwitchOnListOfRegisteredSwitches(IOFSwitch sw){
        listOfSwitchesRegistered.add(sw);
        log.debug("Switch Id {}, was successfully added to the list of registered switches!", sw.getId());
    }
    
    /**
     * Remove a switch from the registered switches list. 
     * @param sw
     */
    public void removeSwitchOnListOfRegisteredSwitches(IOFSwitch sw) {
        boolean removed = listOfSwitchesRegistered.remove(sw);
        if(removed) {
            log.debug("Switch id: {}, was successfully removed from the list of registered switches!", sw.getId());
        } else {
            log.debug("ATTENTION - problems to remove switch id {} from the registered switches list.", sw.getId());
        }
    }

}
