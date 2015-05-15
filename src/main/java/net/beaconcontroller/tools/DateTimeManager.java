package net.beaconcontroller.tools;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DateTimeManager {
    
    public static SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss.SSS"); // Datetime format used in Of-IDPS.
    // Mysql
    //public static SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS"); // Datetime format required by database.
    // Postgres
    private static SimpleDateFormat formatterDB = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS"); // Datetime format required by database.
    private static SimpleDateFormat formatterDBwithoutMilliseconds = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // Datetime format required by database.
    
    protected static Logger log = LoggerFactory.getLogger(LearningSwitchTutorialSolution.class);
    
    
    /**
     * Verify if datetime have milliseconds, if don't has, put it.
     * If the milliseconds don't exists the method will put .000 milliseconds.
     * 
     * Our datetime format don't have time zone.
     * 
     * We need of milliseconds, because the parser of format datetime 
     * gives an error, if the string datetime doesn't has the milliseconds!
     * 
     * @param stringDateDB - Date on format of yyyy-MM-dd HH:mm:ss.SSS or yyyy-MM-dd HH:mm:ss. 
     * @return - String datetime in the format yyyy-MM-dd HH:mm:ss.SSS.
     */
    public static String putMillisecondsOnDatetime(String stringDateDB) {
        if(!stringDateDB.contains(".")) {
            stringDateDB = stringDateDB+".000";
        }
        return stringDateDB;
    }
    
    
    
    /**
     * Convert date to a string with database format. 
     * @param date - A date.
     * @return - String with database date format. 
     */
    public static String dateToStringDBDate(Date date) {
        return formatterDB.format(date).toString();
    }
    
    /**
     * Convert date DB to a string with Java format. 
     * @param date - A date.
     * @return - String with database date format. 
     */
    public static String dateToStringJavaDate(Date date) {
        return formatter.format(date).toString();
    }
    
    /**
     * Get a string from current date.
     * @return - A string DB of current date.
     */
    public static String getStringDBFromCurrentDate() {
        return dateToStringDBDate(getCurrentDate());
    }
    
    /**
     * Get current date.
     * @return - Current date.
     */
    public static Date getCurrentDate() {
        return Calendar.getInstance().getTime();
    }
    
    
    /**
     * Get a string from current date and reduce an amount of seconds.
     * @param seconds - Seconds to be reduced from the current date.
     * @return - A string DB from reduce date.
     */
    public static String getStringDBFromCurrentDateLessAmountOfSeconds(int seconds) {
        Date date = getCurrentDateLessAmountOfSeconds(seconds);
        return dateToStringDBDate(date);
    }
    
    /**
     * Get the current date and reduce an amount of seconds.
     * @param seconds - Seconds to be reduced from the current date.
     * @return - Reduced date.
     */
    public static Date getCurrentDateLessAmountOfSeconds(int seconds) {
        Date currentDate = getCurrentDate();
        return dateLessAmountOfSeconds(currentDate, seconds);
    }
    
    /**
     * Get a date less an amount of seconds and return a string in the format database. 
     * @param date - Date to be reduced.
     * @param seconds - Seconds to be reduced from the date.
     * @return - String with the formated database date. 
     */
    public static String getStringDBdateLessAmountOfSeconds(Date date, int seconds) {
        Date dateLessSeconds = dateLessAmountOfSeconds(date, seconds);
        return dateToStringDBDate(dateLessSeconds);
    }
    
    /**
     * Reduce an amount of seconds from a date.
     * 
     * @param date - Date to be reduced.
     * @param seconds - Seconds to be reduced from the date.
     * @return - Reduced date.
     */
    public static Date dateLessAmountOfSeconds(Date date, int seconds) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.SECOND, (-1 * seconds));
        return calendar.getTime();
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
     * @return Date.
     */
    public static Date stringDateDBtoJavaDate(String datetimeDB) {
        try {
            datetimeDB = putMillisecondsOnDatetime(datetimeDB);
            return formatterDB.parse(datetimeDB);
        } catch (ParseException e) {
                log.debug("ATTENTION!!!, problems to convert datetime.");
                e.printStackTrace();
        }
        return null;
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
     * @param time - yyyy/MM/dd-HH:mm:ss.SSS
     * @return Date.
     */
    public static Date stringDatetoJavaDate(String datetime) {
        try {
            datetime = putMillisecondsOnDatetime(datetime);
            return formatter.parse(datetime);
        } catch (ParseException e) {
                log.debug("ATTENTION!!!, problems to convert datetime.");
                e.printStackTrace();
        }
        return null;
    }
    
    /**
     * 
     * Verify if a datetime is on between a period of time. This period is the
     * current time attribute and minus one amount of time in
     * seconds (periodInSeconds param).
     * 
     * @param analysedDate - Datetime from the alert
     * @param currentDate - current date from the system
     * @param periodInSeconds - the analysis will be between current date less this camp in
     *            seconds and current time.
     * @return true if it's on the required period of time or false if not!
     */
    public static boolean verifyDateTimeRangeInSeconds(Date analysedDate,
            Calendar currentDate, int periodInSeconds) {

        Calendar currentDateLessPeriodInSeconds = Calendar.getInstance();
        currentDateLessPeriodInSeconds.setTime(currentDate.getTime());
        currentDateLessPeriodInSeconds.add(Calendar.SECOND,(periodInSeconds * -1));
        
        // Test if the alert is on the time
        if (analysedDate.after(currentDateLessPeriodInSeconds.getTime()) 
                || analysedDate.equals(currentDateLessPeriodInSeconds.getTime())) {
            
//            log.debug("Alert datetime accepted: {} <{}> {}.", sdf.format(currentDateLessPeriodInSeconds.getTime()),
//                    sdf.format(analysedDate), sdf.format(currentDate.getTime()));            
            
            return true; // alert on the time
        } else {
            
//            log.debug("Alert datetime NOT accepted: {} {} <{}>.", sdf.format(currentDateLessPeriodInSeconds.getTime()),
//                    sdf.format(currentDate.getTime()), sdf.format(analysedDate));
            
            return false; // Alert out of time
        }        
    }
    
    
    /**
     * 
     * Verify if a datetime is on between a period of time. This period is the
     * current time of the system and this same time minus one amount of time in
     * seconds (periodInSeconds param).
     * 
     * @param analysedDate - Datetime from the alert
     * @param periodInSeconds - the analysis will be between current date less this camp in
     *            seconds and current time.
     * @return true if it's on the required period of time or false if not!
     */
    public static boolean verifyDateTimeRangeInSeconds(Date analysedDate, int periodInSeconds) {
        /*
         * Get current datetime from system - to be used on to verify if alerts
         * will be in sensorial, short or long memory of attacks.
         */
        Calendar currentDate = Calendar.getInstance();
        return verifyDateTimeRangeInSeconds(analysedDate, currentDate, periodInSeconds);
    }

}
