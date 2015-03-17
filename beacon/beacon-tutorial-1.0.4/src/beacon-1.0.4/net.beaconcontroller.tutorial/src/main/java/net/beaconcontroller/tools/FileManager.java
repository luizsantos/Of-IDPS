/**
 * Manage reading and writing files.
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 * TODO Doubt! In write or read operations, we always open and close files! Has one more efficient method than this?
 *
 */
package net.beaconcontroller.tools;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.beaconcontroller.tutorial.LearningSwitchTutorialSolution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileManager {

    private String fileName; // File name.
    private String directoryName; // Directory name.
    private String fullPathFileName; // Directory + File name.

    protected static Logger log = LoggerFactory
            .getLogger(LearningSwitchTutorialSolution.class);
    
    /**
     * Start file manager with directory and file name.
     * 
     * @param directoryName -  name of directory.
     * @param fileName - name of file. 
     */
    public FileManager(String directoryName, String fileName) {
        super();
        this.fileName = fileName;
        this.directoryName = directoryName;
        this.fullPathFileName=directoryName+fileName;
    }

    /**
     * Start file manager with just file name - the directory will be the current directory!
     * 
     * @param fileName - name of file.
     * 
     */
    public FileManager(String fileName) {
        super();
        this.fileName = fileName;
        this.directoryName = "./";
        this.fullPathFileName=directoryName+fileName;
    }

    public String getPathFile() {
        return fullPathFileName;
    }

    public String getFileName() {
        return this.fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getDirectoryName() {
        return this.directoryName;
    }

    public void setDirectoryName(String directoryName) {
        this.directoryName = directoryName;
    }
    
    public void delete() {
        
    }
    
    /**
     * Empty the content from a file.
     * 
     * @param text - Contents to be recorded.
     */
    public void emptyFileContent() {
        try {
            FileWriter fstream = new FileWriter(this.fullPathFileName, false);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write("");
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
            log.debug("ATTENTION! Error during writing process on file: {}",
                    this.fullPathFileName);
        }
    }
    
    /**
     * Write informations in a file.
     * 
     * @param text - Contents to be recorded.
     */
    public void writeFile(String text) {
        try {
            FileWriter fstream = new FileWriter(this.fullPathFileName, true);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(text);
            out.write("\n");
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
            log.debug("ATTENTION! Error during writing process on file: {}",
                    this.fullPathFileName);
        }
    }
    
    /**
     * Read file.
     * 
     * @return - the contents from a file.
     */
    public String readFile( ) {
        String text = "";
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(this.fullPathFileName));
            String lineText;
            try {
                while ((lineText = br.readLine()) != null) {
                    text = text + lineText +"\n";
                }
            } catch (IOException e) {
                log.debug("ATTENTION! null text lines on file: {}",
                        this.fullPathFileName);
            }

        } catch (FileNotFoundException e) {
            log.debug("ATTENTION! Error during writing process on file: {}",
                    this.fullPathFileName);
        }
        return text;
    }
    
    /**
     * Generate a hash number from the file contents.
     *  
     * @return - hash number from file contents.
     */
    public String hashFromFile() {
        String fileContents = readFile();
        MessageDigest md5;
        try {
            md5 = MessageDigest.getInstance("MD5");
            md5.update(fileContents.getBytes(), 0, fileContents.length());
            return new BigInteger(1, md5.digest()).toString();
        } catch (NoSuchAlgorithmException e) {
            log.debug("ATTENTION! Error during hash processing from file: {}", this.fullPathFileName);
        }
        return null;
    }
    
    /**
     * Verify if file exists case not create.
     * 
     * @return - FALSE if file already exists or TRUE if file not exists.
     */
    public boolean verifyIfFileExistsCaseNotCreate() {
        File file = new File((this.fullPathFileName));
        try {
            return file.createNewFile();
        } catch (IOException e) {
            log.debug("ATTENTION! Error during the process of open/create file: {}", this.fullPathFileName);
        }
        return false; 
    }
    
    /**
     * Create directory if it doesn't exist!
     */
    public void createDirectory(){
        if(this.directoryName!=null) {
            File directory = new File(this.directoryName);
            // If directory don't exist, create!
            if(!directory.exists()) {
                if(!directory.mkdirs()) {
                    log.debug("ATTENTION! Error during process of directory creation: {}", this.directoryName);
                }
            }
        }
    }
    
}
