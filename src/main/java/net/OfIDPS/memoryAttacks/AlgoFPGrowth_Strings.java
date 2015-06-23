/** 
 * This is an implementation of the FPGROWTH algorithm (Han et al., 2004) that take
 * as input a transaction database where items are represented by strings rather
 * than integers.
 * FPGrowth is described here:
 * <br/><br/>
 * 
 * Han, J., Pei, J., & Yin, Y. (2000, May). Mining frequent patterns without candidate generation. In ACM SIGMOD Record (Vol. 29, No. 2, pp. 1-12). ACM
 * <br/><br/>
 * 
 * This is an optimized version that saves the result to a file.
 *
 * @see FPTree_Strings
 * @author Philippe Fournier-Viger
 * 
 * Changed to Of-IDPS to extract security rules based on the security alerts from IDS and OpenFlow messages. 
 * 
 * @author Luiz Arthur Feitosa dos Santos
 * @email luiz.arthur.feitosa.santos@gmail.com
 * 
 * TODO - REMOVE FILE WRITE we don't need this in the Of-IDPS! 
 */
package net.OfIDPS.memoryAttacks;

/* This file is copyright (c) 2008-2013 Philippe Fournier-Viger
* 
* This file is part of the SPMF DATA MINING SOFTWARE
* (http://www.philippe-fournier-viger.com/spmf).
* 
* SPMF is free software: you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation, either version 3 of the License, or (at your option) any later
* version.
* 
* SPMF is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with
* SPMF. If not, see <http://www.gnu.org/licenses/>.
*/


import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import net.beaconcontroller.IPS.AlertMessage;


public class AlgoFPGrowth_Strings {

	
	// For statistics
	private long startTimestamp; // start time of the latest execution
	private long endTime; // end time of the latest execution
	private int transactionCount = 0; // transaction count in the database
	private int itemsetCount; // number of freq. itemsets found
	
	private int memoryType;
	
	// Minimum support threshold
	public int relativeMinsupp;
	
	public double minsuppGlobal=1;
	
	/*
     * If useDifferentsSupportBasedOnQuantityOfReturnedItems variable is 1, then
     * will use a support number different based on the amount of items returned
     * in the security rule formed by itemsets algorithm. 
     * If is different than 1, then use the same support number to all.
     * 
     * for instance: 
     *  - If returned a rule that contain 5 items (dst,src,proto,sport,dport), 
     *         then user 1.0 support number. 
     *  - If returned a rule that contain 4 (dst,src,proto,sport), 
     *          then use a support number greater, like 3.0, and so on.
     * 
     * The objective is that rules with more items are more specific than we can
     * apply a low support number, because this will match with few packets
     * networks, but security rules with few items are more generic and will match with
     * more packets, than is needed a biggest support to avoid false positives.
     * 
     */
	private int useDifferentsSupportBasedOnQuantityOfReturnedItems=0;
	
	// Object to write the output file
	BufferedWriter writer = null; 

	// Store security alerts texts
	private String stringAttacksMemory="";

	//	Private ArrayList<AlertMessage> listaRegrasAlertasIDS = new ArrayList<AlertMessage>();
	
	// Store security rules without duplicates
	Map<String,AlertMessage> listSecurityRulesNoDuplicates = new HashMap<String, AlertMessage>();
	
	/*
     * Set the quantity of items that is required on the returned rules.
     * 
     * Then, only will be returned, rules that have at least the number informed
     * in quantityOfItemsRequiredOnRule variable.
     * 
     * The number 1 (default) is the minimum and 5 is the max. All 5 items that
     * can be considered are: 
     * destination IP, source IP, protocol, source port, destination port). 
     * 
     * Note that description and priority fields on the alert
     * (see AlertMessage class) aren't be considered in this count, because we can't create
     * security rules with only this fields!
     */
	private int quantityOfItemsRequiredOnRule=1;


	public int getQuantityOfItemsRequiredOnRule() {
        return quantityOfItemsRequiredOnRule;
    }

	 /**
     * Set the minimum of items returned by the itemsets algorithm, the minimum
     * is 1 and the max is 5. Attention, this is controlled by the method, thus
     * numbers minors than 1 or greater that 5 are automatically set to 1.
     * 
     * @param itensQuantity - Number that represent the minimum of items returned by the itemsets algorithm.
     */
    public void setQuantityOfItemsRequiredOnRule(int itensQuantity) {
        if (itensQuantity<=5 || itensQuantity>=1) {
            this.quantityOfItemsRequiredOnRule = itensQuantity; 
        } else {
            System.out.println("Attention! Value is out of range 1 up to 5, to construct security rules... then this will be executed with default value 1.");
            this.quantityOfItemsRequiredOnRule=1;
        }
        
    }


    /**
	 * Default constructor
	 */
	public AlgoFPGrowth_Strings(int memoryType) {
		this.memoryType=memoryType;
	}

    /**
     * Run the itemsets algorithm! Here will be returned rules with at least 1
     * item and we use different support number for different amounts of
     * returned items.
     * 
     * @param input - The file path of an input transaction database.
     * @param output - The path of the desired output file.
     * @throws IOException - Exception if error while writing the file
     */
    public Map<String, AlertMessage> runAlgorithm(String input, String output) throws FileNotFoundException, IOException {
        // Require at least 1 item.
        this.setQuantityOfItemsRequiredOnRule(1);
        // Set to 1 to use different support numbers.
        this.useDifferentsSupportBasedOnQuantityOfReturnedItems=1;
        /*
         * Run itemsets algorithm start support number in 0.1, but this will be
         * ignored because of value of value 1 on the
         * useDifferentsSupportBasedOnQuantityOfReturnedItems variable.
         */
        this.runAlgorithm(input, output, 0.1);
        return listSecurityRulesNoDuplicates;        
    }	
	
	
	
   /**
     * Run the itemsets algorithm using a minimum number of quantity items 
     * that (itemsQuantity) that must be returned in the rule.
     *  
     * @param input - Input the file path of an input transaction database.
     * @param output - Output the path of the desired output file
     * @param minsupp - Minsupp minimum support threshold as a percentage (double)
     * @param itemsQuantity - Least amount of items required on the returned rule.
     * @throws - IOException exception if error while writing the file
     */
    public Map<String, AlertMessage> runAlgorithm(String input, String output, double minsupp, int itemsQuantity) throws FileNotFoundException, IOException {
        // Set the minimum quantity of required items in a rule.
        this.setQuantityOfItemsRequiredOnRule(itemsQuantity);
        // Run itemsets algorithm.
        this.runAlgorithm(input, output, minsupp);
        return listSecurityRulesNoDuplicates;        
    }

	/**
	 * Run the itemsets algorithm (original - main).
	 * @param input the file path of an input transaction database.
	 * @param output the path of the desired output file
	 * @param minsupp minimum support threshold as a percentage (double)
	 * @throws IOException exception if error while writing the file
	 */
	public Map<String, AlertMessage> runAlgorithm(String input, String output, double minsupp) throws FileNotFoundException, IOException {
		
	    minsuppGlobal = minsupp;
	    // Record the start time
		startTimestamp = System.currentTimeMillis();
		// Reinitialize the number of itemsets found to 0
		itemsetCount =0;
		// Prepare the output file
		writer = new BufferedWriter(new FileWriter(output)); 
		
		// (1) PREPROCESSING: Initial database scan to determine the frequency of each item
		// The frequency is store in a map where:
		// key: item   value: support count
		final Map<String, Integer> mapSupport = new HashMap<String, Integer>();
		// call this method  to perform the database scan
		scanDatabaseToDetermineFrequencyOfSingleItems(input, mapSupport);
		
		// Convert the absolute minimum support to a relative minimum support
		// by multiplying by the database size.
		this.relativeMinsupp = (int) Math.ceil(minsupp * transactionCount);
		
		// (2) Scan the database again to build the initial FP-Tree
		// Before inserting a transaction in the FPTree, we sort the items
		// by descending order of support.  We ignore items that
		// do not have the minimum support.
		
		// Create the FPTree
		FPTree_Strings tree = new FPTree_Strings();
		
        Scanner reader = new Scanner(input);

		
		//BufferedReader reader = new BufferedReader(new FileReader(input));
		String line;
		// For each line (transaction) in the input file until the end of file
        while(reader.hasNextLine()!= false){
            line = reader.nextLine();
			// If the line is  a comment, is  empty or is a
			// Kind of metadata
			if (line.isEmpty() == true ||
					line.charAt(0) == '#' || line.charAt(0) == '%'
							|| line.charAt(0) == '@') {
				continue;
			}
			
			// Split the transaction into items
			String[] lineSplited = line.split(" ");
			// Create an array list to store the items
			List<String> transaction = new ArrayList<String>();
			// For each item in the transaction
			for(String itemString : lineSplited){  
				// If it is frequent, add it to the transaction
				// Otherwise not because it cannot be part of a frequent itemset.
				if(mapSupport.get(itemString) >= relativeMinsupp){
					transaction.add(itemString);	
				}
			}
			// Sort item in the transaction by descending order of support
			Collections.sort(transaction, new Comparator<String>(){
				public int compare(String item1, String item2){
					// Compare the support
					int compare = mapSupport.get(item2) - mapSupport.get(item1);
					// If the same support, we check the lexical ordering!
					if(compare == 0){ 
						return item1.compareTo(item2);
					}
					// Otherwise use the support
					return compare;
				}
			});
			// Add the sorted transaction to the fptree.
			tree.addTransaction(transaction);
		}
		// Close the input file
		//reader.close();
		
		// We create the header table for the tree
		tree.createHeaderList(mapSupport);
		
		// (5) We start to mine the FP-Tree by calling the recursive method.
		// Initially, the prefix alpha is empty.
		String[] prefixAlpha = new String[0];
		if(tree.headerList.size() > 0) {
			fpgrowth(tree, prefixAlpha, transactionCount, mapSupport);
		}
		
		// Close the output file
		writer.close();
		// Record the end time
		endTime= System.currentTimeMillis();
		
//		print(tree.root, " ");
		
		return listSecurityRulesNoDuplicates;
	}

	
//	private void print(FPNode node, String indentation) {
//		System.out.println(indentation + "NODE : " + node.itemID + " COUNTER" + node.counter);
//		for(FPNode child : node.childs) {
//			print(child, indentation += "\t");
//		}
//	}

	/**
	 * This method scans the input database to calculate the support of single items
	 * 
	 * @param input - The path of the input file
	 * @param mapSupport - A map for storing the support of each item (key: item, value: support)
	 * @throws IOException - exception if error while writing the file
	 */
	private void scanDatabaseToDetermineFrequencyOfSingleItems(String input,
			final Map<String, Integer> mapSupport)
			throws FileNotFoundException, IOException {
		//Create object for reading the input file
		//BufferedReader reader = new BufferedReader(new FileReader(input));
	    Scanner reader = new Scanner(input);
		String line;
		// For each line (transaction) until the end of file
		while(reader.hasNextLine()!= false){
		    line = reader.nextLine();
			// If the line is  a comment, is  empty or is a
			// Kind of metadata
			if (line.isEmpty() == true ||
					line.charAt(0) == '#' || line.charAt(0) == '%'
							|| line.charAt(0) == '@') {
				continue;
			}
			
			// Aplit the transaction into items
			String[] lineSplited = line.split(" ");
			 // For each item in the transaction
			for(String itemString : lineSplited){ 
				// Increase the support count of the item
				Integer count = mapSupport.get(itemString);
				if(count == null){
					mapSupport.put(itemString, 1);
				}else{
					mapSupport.put(itemString, ++count);
				}
			}
			// Increase the transaction count
			transactionCount++;
		}
		// Close the input file
		//reader.close();
	}


	/**
	 * This method mines pattern from a Prefix-Tree recursively
	 * 
	 * @param tree - The Prefix Tree
	 * @param prefix - The current prefix "alpha"
	 * @param mapSupport - The frequency of each item in the prefix tree.
	 * @throws IOException -  exception if error writing the output file
	 */
	private void fpgrowth(FPTree_Strings tree, String[] prefixAlpha, int prefixSupport, Map<String, Integer> mapSupport) throws IOException {
		// We need to check if there is a single path in the prefix tree or not.
		if(tree.hasMoreThanOnePath == false){
			// That means that there is a single path, so we 
			// add all combinations of this path, concatenated with the prefix "alpha", to the set of patterns found.
			addAllCombinationsForPathAndPrefix(tree.root.childs.get(0), prefixAlpha); // CORRECT?
			
		}else{ // There is more than one path
			fpgrowthMoreThanOnePath(tree, prefixAlpha, prefixSupport, mapSupport);
		}
	}
	
	/**
	 * Mine an FP-Tree having more than one path.
	 * 
	 * @param tree - The FP-tree
	 * @param prefix - The current prefix, named "alpha"
	 * @param mapSupport - The frequency of items in the FP-Tree
	 * @throws IOException - Exception if error writing the output file
	 */
	private void fpgrowthMoreThanOnePath(FPTree_Strings tree, String [] prefixAlpha, int prefixSupport, Map<String, Integer> mapSupport) throws IOException {
		// We process each frequent item in the header table list of the tree in reverse order.
		for(int i= tree.headerList.size()-1; i>=0; i--){
			String item = tree.headerList.get(i);
			
			int support = mapSupport.get(item);
			// If the item is not frequent, we skip it
			if(support <  relativeMinsupp){
				continue;
			}
			// Create Beta by concatening Alpha with the current item
			// and add it to the list of frequent patterns
			String [] beta = new String[prefixAlpha.length+1];
			System.arraycopy(prefixAlpha, 0, beta, 0, prefixAlpha.length);
			beta[prefixAlpha.length] = item;
			
			// Calculate the support of beta
			int betaSupport = (prefixSupport < support) ? prefixSupport: support;
			// Save beta to the output file
			writeItemsetToFile(beta, betaSupport);
			
			// === Construct beta's conditional pattern base ===
			// It is a subdatabase which consists of the set of prefix paths
			// In the FP-tree co-occuring with the suffix pattern.
			List<List<FPNode_Strings>> prefixPaths = new ArrayList<List<FPNode_Strings>>();
			FPNode_Strings path = tree.mapItemNodes.get(item);
			while(path != null){
				// If the path is not just the root node
				if(path.parent.itemID != null){
					// Create the prefixpath
					List<FPNode_Strings> prefixPath = new ArrayList<FPNode_Strings>();
					// Add this node.
					prefixPath.add(path);   // NOTE: we add it just to keep its support,
					// Actually it should not be part of the prefixPath
					
					//Recursively add all the parents of this node.
					FPNode_Strings parent = path.parent;
					while(parent.itemID != null){
						prefixPath.add(parent);
						parent = parent.parent;
					}
					// Add the path to the list of prefixpaths
					prefixPaths.add(prefixPath);
				}
				// We will look for the next prefixpath
				path = path.nodeLink;
			}
			
			// (A) Calculate the frequency of each item in the prefixpath
			Map<String, Integer> mapSupportBeta = new HashMap<String, Integer>();
			// For each prefixpath
			for(List<FPNode_Strings> prefixPath : prefixPaths){
				// The support of the prefixpath is the support of its first node.
				int pathCount = prefixPath.get(0).counter;  
				 // For each node in the prefixpath,
				// Except the first one, we count the frequency
				for(int j=1; j<prefixPath.size(); j++){ 
					FPNode_Strings node = prefixPath.get(j);
					// If the first time we see that node id
					if(mapSupportBeta.get(node.itemID) == null){
						// Just add the path count
						mapSupportBeta.put(node.itemID, pathCount);
					}else{
						// Otherwise, make the sum with the value already stored
						mapSupportBeta.put(node.itemID, mapSupportBeta.get(node.itemID) + pathCount);
					}
				}
			}
			
			// (B) Construct beta's conditional FP-Tree
			FPTree_Strings treeBeta = new FPTree_Strings();
			// Add each prefixpath in the FP-tree
			for(List<FPNode_Strings> prefixPath : prefixPaths){
				treeBeta.addPrefixPath(prefixPath, mapSupportBeta, relativeMinsupp); 
			}  
			// Create the header list.
			treeBeta.createHeaderList(mapSupportBeta); 
			
			// Mine recursively the Beta tree if the root as child(s)
			if(treeBeta.root.childs.size() > 0){
				// Recursive call
				fpgrowth(treeBeta, beta, betaSupport, mapSupportBeta);
			}
		}
		
	}

	/**
	 * This method is for adding recursively all combinations of nodes in a path, concatenated with a given prefix,
	 * to the set of patterns found.
	 * 
	 * @param nodeLink - The first node of the path
	 * @param prefix - The prefix
	 * @param minsupportForNode - The support of this path.
	 * @throws IOException 
	 */
	private void addAllCombinationsForPathAndPrefix(FPNode_Strings node, String[] prefix) throws IOException {
		// Concatenate the node item to the current prefix
		String [] itemset = new String[prefix.length+1];
		System.arraycopy(prefix, 0, itemset, 0, prefix.length);
		itemset[prefix.length] = node.itemID;

		// Save the resulting itemset to the file with its support
		writeItemsetToFile(itemset, node.counter);
			
		if(node.childs.size() != 0) {
			addAllCombinationsForPathAndPrefix(node.childs.get(0), itemset);
			addAllCombinationsForPathAndPrefix(node.childs.get(0), prefix);
		}
	}
	

	/**
	 * Write a frequent itemset that is found to the output file.
	 * 
	 * TODO - Turn in optional, the output write in file.  
	 * 
	 */
	private void writeItemsetToFile(String [] itemset, int support) throws IOException {
		// Increase the number of itemsets found for statistics purpose
		itemsetCount++;
		
		int quantity = 0;
		
		AlertMessage alertMsg = new AlertMessage();
		
		// Create a string buffer 
		StringBuffer buffer = new StringBuffer();
		// Write items from the itemset to the stringbuffer
		for(int i=0; i< itemset.length; i++){
			buffer.append(itemset[i]);
			//System.out.print(itemset[i]);
			
			String field = itemset[i];
			//System.out.println("-----|>src:"+field.subSequence(0, 3));
			//System.out.println("----->src:"+field.subSequence(3, campo.length()));
			String descriptionField = (String) field.subSequence(0, 3);
			int fieldValue = Integer.MAX_VALUE;
			try {
			 fieldValue = Integer.parseInt((String) field.subSequence(3, field.length()));
			} catch (Exception e) {
                // TODO: handle exception
			    fieldValue = Integer.MAX_VALUE;
            }

			/*
			 * Set the analyzed field in the correct Alert Message class variable. 
			 * Case the returned rule don't have all fields to be set on Alert 
			 * Message object, this missing fields will be recorded with Integer.MAX_VALUE.
			 * 
			 */
			if (descriptionField.equals("src")) {    
			    alertMsg.setNetworkSource(fieldValue);
			    quantity++;
			} else if (field.subSequence(0, 3).equals("dst")) {
			    alertMsg.setNetworkDestination(fieldValue);
			    quantity++;
			} else if (field.subSequence(0, 3).equals("pro")) {
			    alertMsg.setNetworkProtocol(fieldValue);
			    quantity++;
			} else if (field.subSequence(0, 3).equals("spo")) {
			    alertMsg.setTransportSource(fieldValue);
			    quantity++;
			} else if (field.subSequence(0, 3).equals("dpo")) {
			    alertMsg.setTransportDestination(fieldValue);
			    quantity++;
			} else if (field.subSequence(0, 3).equals("pri")) {
			    alertMsg.setPriorityAlert(fieldValue);
			} else if (field.subSequence(0, 3).equals("des")) {
			    String desc = (String) field.subSequence(3, field.length());
			    alertMsg.setAlertDescription(desc);
			}
			
			stringAttacksMemory = stringAttacksMemory+itemset[i];
			if(i != itemset.length-1){
				buffer.append(' ');
				//System.out.print(" ");
				stringAttacksMemory = stringAttacksMemory+" ";
			}
		}
		// Append the support of the itemset.
		buffer.append(':');
		buffer.append(support);
		//System.out.println(" :"+support);
		stringAttacksMemory = stringAttacksMemory+" :"+support+"\n";
		// Set the support number returned, this can be used before.
		alertMsg.setSupportApriori(support);
	    
		// Add this security rule to the list.
		// Generate key to be used on Map.
		String networkSocketKey = alertMsg.getKeyFromNetworkSocket();
		
        /*
         * Check if this rules have ports without have the protocol. If this is
         * true don't use this rules, because we can't use a rule this way.
         */
		
        if (alertMsg.getNetworkSource() == Integer.MAX_VALUE
                && alertMsg.getNetworkDestination() == Integer.MAX_VALUE
                && alertMsg.getNetworkProtocol() == Integer.MAX_VALUE
                && alertMsg.getTransportSource() == Integer.MAX_VALUE
                && alertMsg.getTransportDestination() == Integer.MAX_VALUE
                && (alertMsg.getPriorityAlert() != Integer.MAX_VALUE 
                || !alertMsg.getAlertDescription().equals("none"))) {
            //System.out.println("Don't use this rule, because it have just alert priority or description!");
        } else {
            // If have protocol information.
            if (alertMsg.getNetworkProtocol() != Integer.MAX_VALUE) {
                // Verify if only have network protocol field
                if (alertMsg.getNetworkSource() == Integer.MAX_VALUE
                        && alertMsg.getNetworkDestination() == Integer.MAX_VALUE
                        && alertMsg.getTransportSource() == Integer.MAX_VALUE
                        && alertMsg.getTransportDestination() == Integer.MAX_VALUE) {
//                    System.out.println("Only has network PROTOCOL field, this rule can be very aggressive, them we don't use this!");
//                    alertMsg.printMsgAlert();
                } else {
                    // Verify if use different support to different items
                    // quantity is enable.
                    if (useDifferentsSupportBasedOnQuantityOfReturnedItems == 1) {
                        // If enable
                        addToListAplyingDifferentsSupportBasedOnQuantityOfReturnedItems(
                                quantity, alertMsg, networkSocketKey);
                    } else {
                        // If disable.
                        addToListVerifyingTheQuantityOfItemsRequiredOnRule(
                                quantity, alertMsg, networkSocketKey);
                    }
                }
            } else {
                // If don't have protocol information, have Integer.MAX_VALUE!
                // If enter here it have Integer.MAX_VALUE that means: don't have protocol.
                if (alertMsg.getTransportSource() == Integer.MAX_VALUE
                        && alertMsg.getTransportDestination() == Integer.MAX_VALUE) {
                    // OK... Don't have ports.
                    // Verify if use different support to different items quantity is enable.
                    if (useDifferentsSupportBasedOnQuantityOfReturnedItems==1) {
                        // If enable different supports.
                        addToListAplyingDifferentsSupportBasedOnQuantityOfReturnedItems(quantity, alertMsg, networkSocketKey);
                    } else {
                        // If disable different supports.
                        addToListVerifyingTheQuantityOfItemsRequiredOnRule(quantity, alertMsg, networkSocketKey);
                    }                    
                } else {
                    //System.out.println("We won't use this rule, because has ports but don't have protocol!");
                }
            }

        }
        
        quantity = 0;
		
        // Write the strinbuffer and create a newline so that we are
		// Ready for the next itemset to be written
		writer.write(buffer.toString());
		writer.newLine();
	}

    /**
     * Add to list of rules using differents support numbers based 
     * on quantity of fields presents in the rules.
     * 
     * More fields less support is required! Less fields more support is necessary...
     * 
     * @param numberOfFieldsOnRule - Quantity of fields presents on the rule.
     * @param alertMsg - Rule in the alert message form!
     * @param key - Rule socket netkork key.
     */
    private void addToListAplyingDifferentsSupportBasedOnQuantityOfReturnedItems(int numberOfFieldsOnRule,
            AlertMessage alertMsg, String key) {
        
        //System.out.println("****> Total of transactions: " + transactionCount);
        switch (this.memoryType) {
            case MemorysAttacks.MEMORY_SENSORIAL:
                System.out.println("ATTENTION!!! Sensorial memory does not use itemset method!");
            break;
            case MemorysAttacks.MEMORY_SHORT:
                System.out.println("Short memory using method 1");
                method_1_ToBadMemories(numberOfFieldsOnRule, alertMsg, key);
            break;
            case MemorysAttacks.MEMORY_LONG_BAD:
                System.out.println("Long bad memory using method 1");
                method_1_ToBadMemories(numberOfFieldsOnRule, alertMsg, key);
            break;
            case MemorysAttacks.MEMORY_LONG_GOOD:
                //System.out.println("Long good memory using method 2");
                method_2_ToLongGoodMemory(numberOfFieldsOnRule, alertMsg, key);
            break;
            default:
                System.out.println("ATTENTION!!! Not found a method to process this alerts on " +
                		"itemset algorithm (AlgoFPGrowth_String class)! " +
                		"Please use a valid method selecting a valid memory number/id...");
                break;
        }
        
    }

    /**
     * First method used to get rules to bad memories.
     * 
     * @param numberOfFieldsOnRule - Quantity of fields presents on the rule.
     * @param alertMsg - Rule in the alert message form!
     * @param key - Rule socket netkork key.
     */
    private void method_1_ToBadMemories(int numberOfFieldsOnRule,
            AlertMessage alertMsg, String key) {
        if (numberOfFieldsOnRule <= 1) {
            int newMinsupp = (int) Math.ceil(0.9 * transactionCount);
            if (alertMsg.getSupportApriori()>=newMinsupp) {
                addRuleOnListOfSecurityRules(alertMsg, key);
                //System.out.println("\t\t\t{{{>(1) "+numberOfFieldsOnRule+" items - "+newMinsupp+ " - "+alertMsg.getSupportApriori()+"/"+transactionCount);
            }
        } else if (numberOfFieldsOnRule == 2) {
            int newMinsupp = (int) Math.ceil(0.7 * transactionCount);
            if (alertMsg.getSupportApriori()>=newMinsupp) {
                addRuleOnListOfSecurityRules(alertMsg, key);
                //System.out.println("\t\t\t{{{>(2) "+numberOfFieldsOnRule+" items - "+newMinsupp+ " - "+alertMsg.getSupportApriori()+"/"+transactionCount);
            }
        } else if (numberOfFieldsOnRule == 3) {
            int newMinsupp = (int) Math.ceil(0.5 * transactionCount);
            if (alertMsg.getSupportApriori()>=newMinsupp) {
                addRuleOnListOfSecurityRules(alertMsg, key);
                //System.out.println("\t\t\t{{{>(3) "+numberOfFieldsOnRule+" items - "+newMinsupp+ " - "+alertMsg.getSupportApriori()+"/"+transactionCount);
            }
        } else if (numberOfFieldsOnRule == 4) {
            int newMinsupp = (int) Math.ceil(0.3 * transactionCount);
            if (alertMsg.getSupportApriori()>=newMinsupp) {
                addRuleOnListOfSecurityRules(alertMsg, key);
                //System.out.println("\t\t\t{{{>(4) "+numberOfFieldsOnRule+" items - "+newMinsupp+ " - "+alertMsg.getSupportApriori()+"/"+transactionCount);
            }
        } else {
            addRuleOnListOfSecurityRules(alertMsg, key);
            int newMinsupp = (int) Math.ceil(0.1 * transactionCount);
            //System.out.println("\t\t\t{{{>(5) "+numberOfFieldsOnRule+" items - "+newMinsupp+ " - "+alertMsg.getSupportApriori()+"/"+transactionCount);
        }
    }
    
    /**
     * First method used to get rules to bad memories.
     * 
     * @param numberOfFieldsOnRule - Quantity of fields presents on the rule.
     * @param rule - Rule in the alert message form!
     * @param key - Rule socket netkork key.
     */
    private void method_2_ToLongGoodMemory(int numberOfFieldsOnRule,
            AlertMessage rule, String key) {
        int sport=0;
        int dport=0;
        // Verify if the minimum support was hit!
        int novoMinsupp = (int) Math.ceil(0.1 * transactionCount);
        if (rule.getSupportApriori() >= novoMinsupp && transactionCount > 500) {
            // verify if source, destination, and protocol not exists! Case true
            // return and don't do nothing
            if ((rule.getNetworkSource() == Integer.MAX_VALUE)
                    || (rule.getNetworkDestination() == Integer.MAX_VALUE)
                    || (rule.getNetworkProtocol() == Integer.MAX_VALUE)) {
                return;
            } else {
                // Verify if exist source port!
                if (rule.getTransportSource() != Integer.MAX_VALUE) {
                    // if yes, set sport to 1.
                    sport = 1;
                }
                // verify if exist destination port!
                if (rule.getTransportDestination() != Integer.MAX_VALUE) {
                    // if yes, set dport to 1.
                    dport = 1;
                }
                // Now verify if don't exist any port! If it's true don't make
                // anything and just return!
                if (sport == 0 && dport == 0) {
                    return;
                } else {
                    // if we have ports...
                    // we have both ports?
                    if ((sport == 1 && dport == 1)
                            || (sport == 0 && dport == 1)
                            || (sport == 1 && dport == 0)) {
                        // Add coming and going rules  
                        addRuleOnListOfSecurityRules(rule, key);
                        addInvertedRule(rule);
                    }
                }
            }
        }
    }
    
    /**
     * This is used to invert the source and destinations fields from a rule!
     * Then the original rule, for instance, create the rule to the packet 
     * going out and this method create the rule to the packet going back. 
     * 
     * @param rule - A security rule/alert.
     * @return - A inverted rule/alert
     */
    private void addInvertedRule(AlertMessage rule) {
        AlertMessage ruleInverted = new AlertMessage();
        ruleInverted.setPriorityAlert(rule.getPriorityAlert());
        ruleInverted.setAlertDescription(rule.getAlertDescription());
        ruleInverted.setNetworkSource(rule.getNetworkDestination());
        ruleInverted.setNetworkDestination(rule.getNetworkSource());
        ruleInverted.setNetworkProtocol(rule.getNetworkProtocol());
        ruleInverted.setTransportSource(rule.getTransportDestination());
        ruleInverted.setTransportDestination(rule.getTransportSource());
        ruleInverted.setSupportApriori(-1); // indicate the inverse rule!
        
        String keyInverted = Integer.toString(ruleInverted.getNetworkSource())+
                Integer.toString(ruleInverted.getNetworkDestination())+
                Integer.toString(ruleInverted.getNetworkProtocol())+
                Integer.toString(ruleInverted.getTransportSource())+
                Integer.toString(ruleInverted.getTransportDestination());
        
        addRuleOnListOfSecurityRules(ruleInverted, keyInverted);
    }

    /**
     * Add to list of rules using the quantity of items returned by the rule.
     * 
     * @param quantity - Quantity of fields presents on the rule.
     * @param alertMsg - Rule in the alert message form!
     * @param key - Rule socket netkork key.
     */
    private void addToListVerifyingTheQuantityOfItemsRequiredOnRule(int quantity,
            AlertMessage alertMsg, String key) {
        if (quantity >= quantityOfItemsRequiredOnRule) {                    
            addRuleOnListOfSecurityRules(alertMsg, key);
        } else {
            //System.out.println("::> Have only "+quantity+" of "+quantityOfItemsRequiredOnRule+" required items! Remember we don't count priority and description.");
        }
    }


    /**
     * Add rule (rule is a alert message object) on the list of security rules.
     * 
     * @param alertMsg - Rule in the alert message form!
     * @param key - Rule socket netkork key.
     */
    private void addRuleOnListOfSecurityRules(AlertMessage alertMsg, String key) {
        
        AlertMessage msgAlertAlreadyCadastred = null;
        msgAlertAlreadyCadastred = listSecurityRulesNoDuplicates.get(key);
        if(msgAlertAlreadyCadastred==null) {
            //System.out.println(">>Add new Key: "+key);
            //mostraMsgAlerta(alertMsg);
            listSecurityRulesNoDuplicates.put(key, alertMsg);
        } else {
            //System.out.println("++Key already exist: "+ key);
            //System.out.print("\tOld: ");
            //printRule(msgAlertAlreadyCadastred);
            //System.out.print("\tNew: ");
            //printRule(alertMsg);
            
            /**
             *  When smaller the priority, greater is the level of security compromise.
             *  4 - packet/flow normal, 3 - low, 2 - medium, 1 - high. 
             *  Integer.MAX_VALUE - without priority number!
             */
            if(alertMsg.getPriorityAlert() < msgAlertAlreadyCadastred.getPriorityAlert()) {
                //System.out.println("\t\t--The new key has higher priority (the lower number represent higher security priority)");
                // Update priority and description, because this alert has more priority security!
                msgAlertAlreadyCadastred.setPriorityAlert(alertMsg.getPriorityAlert());
                msgAlertAlreadyCadastred.setAlertDescription(alertMsg.getAlertDescription());
            }
            
            if(alertMsg.getSupportApriori() > msgAlertAlreadyCadastred.getSupportApriori()) {
                //System.out.println("\t\t--Key has support number higher!");
                msgAlertAlreadyCadastred.setSupportApriori(alertMsg.getSupportApriori());
            }
        }
    }
    
    /**
     * Print rule/alert - we can use the print method of Alert Message to make the same!
     * 
     * @param currentRule - Rule that will be printed.
     */
    private static void printRule(AlertMessage currentRule) {
        System.out.println(currentRule.getNetworkSource()+" "+currentRule.getTransportSource()+" "+
                        currentRule.getNetworkDestination()+" "+currentRule.getTransportDestination()+" "+
                        currentRule.getNetworkProtocol()+" "+
                        currentRule.getPriorityAlert()+" "+currentRule.getAlertDescription()+
                        " "+currentRule.getSupportApriori()
                        );
    }

	/**
	 * Print statistics about the algorithm execution to System.out.
	 */
	public void printStats() {
		System.out
				.println("=============  FP-GROWTH - STATS =============");
		long temps = endTime - startTimestamp;
		System.out.println(" Transactions count from database : " + transactionCount);
		System.out.println(" Frequent itemsets count : " + itemsetCount); 
		System.out.println(" Total time ~ " + temps + " ms");
		System.out
				.println("===================================================");
	}

}
