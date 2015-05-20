package net.OfIDPS.memoryAttacks;

import java.util.Date;

import net.beaconcontroller.tools.DateTimeManager;
import net.beaconcontroller.tutorial.CONFIG;
import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LongTermMemory extends Thread {
    
    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    /*
     * Time to wait until execute again the main method contained in the Thread (method run).
     */
    public static final int TIME_TO_WAIT= 3;
    
    /**
     * 
     * Method responsible to run the Thread and send OpenFlow statistics messages request.
     * 
     */
    public void run() {
        log.debug("Start Thread that is responsible to construct Long-Term memory.");
        while (true) {
            if (MemorysAttacks.disableLongMemory != 1) {
                longBadMemory();
            } else {
                log.debug("\t!!!!!!!! ATTENTION, Long memory is DISABLED!!!!!!!!  to change this setup to 0 (zero) the variable disableLongMemory on MemoryAttacks class...");
            }
            // Time to waiting
            log.debug("Waiting {} seconds to rerun Long-term memory", TIME_TO_WAIT);
            waitTimeInSeconds(TIME_TO_WAIT);
            
        }
        
    }

    private void longBadMemory() {
        
        Date dateStart = DateTimeManager.getCurrentDate();
        
        log.debug("Long-term Memory");
        
        Date dateStop = DateTimeManager.getCurrentDate();
        long diffSeconds = DateTimeManager.differenceBetweenTwoDatesInSeconds(dateStart, dateStop);
        log.debug("End of LONG memory! {} - {} -> {} seconds", 
                DateTimeManager.dateToStringJavaDate(dateStart), 
                DateTimeManager.dateToStringJavaDate(dateStop),
                diffSeconds);
        
    }
    
    /**
     * Waiting a period of seconds 
     * 
     * @param timeInSeconds
     *            the Thread will wait a period of time.
     */
    private void waitTimeInSeconds(int timeInSeconds) {
        try {
            sleep(timeInSeconds * 1000);
        } catch (InterruptedException e) {
            log.debug("Problem with sleep in LongTermMemory:waitTimeInSeconds");
            e.printStackTrace();
        }
    }

}
