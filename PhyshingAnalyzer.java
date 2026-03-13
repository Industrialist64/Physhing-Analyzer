/*
    PhyshingAnalyzer.java -> A URL and Threat Scanner
    Features:
        - 
*/

import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import java.net.URI;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.util.Scanner;
import java.util.LinkedList;
import java.util.ArrayList;
import java.util.regex.*;






// Describes a Single Detected Threat 

class RedFlag {
    public String type;
    public String threatLevel; // Extreme, High, Medium, Low
    public String description;  // Readable explanation
    public String evidence; // Value that triggered the flag

    public RedFlag(String type, String threatLevel, String description, String evidence){
        this.type = type;
        this.threatLevel = threatLevel;
        this.description = description;
        this.evidence = evidence;
    }
}

// Full Analysis for URL/ Email

class SeverityScore{
    public String inputTarget; // Raw Data
    public String type;  // URL, Email
    public int score = 0;
    public String severityLevel = "SAFE";

    // Detected threats added to tail
    public LinkedList<RedFlag> redFlags = new LinkedList<>();

    // Logging Time
    public long timeScan;

    public SeverityScore(String inputTarget, String type){
        this.inputTarget = inputTarget;
        this.type = type;
        this.timeScan = system.currentTimeMillis();
    }
}

// Record for in-memory history

class ScanHistory{
    public String inputTarget;
    public String severity;
    public int score;
    public long timeStamp;

    public ScanHistory(String inputTarget, String severity, int score, long timestamp){
        this.inputTarget = target;
        this.severity = severity;
        this.score = score;
        this.timestamp = timestamp;
    }

    public String toString(){
        return new java.util.Date(timeStamp) + ", " + severity + ", " + score + ", " + target;
    }

}

// Main Application ----------------------------------------------------------------------------------------------

public class PhyshingAnalyzer{

    // Live phishing domain blacklist -> 
    private ArrayList<String> phishingBlacklist;

    private ArrayList<String> staticWhitelist;
    private ArrayList<String> staticBlacklist;


    // Parralel arrays for homoglyph lookalike table
    private ArrayList<String> homohlyphImposters;
    private ArrayList<String> homohlyphValues;

    // Timestamp Logs of Found Vulnerabilies this Session
    private LinkedList<ScanHistory> scanLogs;

    // File path for various stored whitelisted/ blacklisted domains
    private static final String LOGS = "ScanLog.txt";
    private static final String WHITELISTED = "Whitelist.txt";
    private static final String BLACKLISTED = "Blacklist.txt";

    public PhyshingAnalyzer(){
        
        this.phishingBlacklist = new ArrayList<>(50_000);

        this.staticWhitelist = new ArrayList<>();
        this.staticBlacklist = new ArrayList<>();
        this.homoglyphImposters = new ArrayList<>();
        this.homoglyphValues= new ArrayList<>();

        // Initiate Scan History
        this.scanLogs = new LinkedList<>();


        banner();
        System.out.println("[*] Initializing Analysis...");
        loadHomoglyphs();
        loadStaticLists();
        this.phishingBlacklist = fetchActiveBlacklist();
        System.out.println("[*] Program Ready\n");
    }

    private void banner() {
        System.out.println("""
@@@@@@@   @@@  @@@  @@@ @@@   @@@@@@   @@@  @@@  @@@  @@@  @@@   @@@@@@@@     @@@@@@   @@@  @@@   @@@@@@   @@@       @@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@   
@@@@@@@@  @@@  @@@  @@@ @@@  @@@@@@@   @@@  @@@  @@@  @@@@ @@@  @@@@@@@@@    @@@@@@@@  @@@@ @@@  @@@@@@@@  @@@       @@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@@  @@! !@@  !@@       @@!  @@@  @@!  @@!@!@@@  !@@          @@!  @@@  @@!@!@@@  @@!  @@@  @@!       @@! !@@       @@!  @@!       @@!  @@@  
!@!  @!@  !@!  @!@  !@! @!!  !@!       !@!  @!@  !@!  !@!!@!@!  !@!          !@!  @!@  !@!!@!@!  !@!  @!@  !@!       !@! @!!      !@!   !@!       !@!  @!@  
@!@@!@!   @!@!@!@!   !@!@!   !!@@!!    @!@!@!@!  !!@  @!@ !!@!  !@! @!@!@    @!@!@!@!  @!@ !!@!  @!@!@!@!  @!!        !@!@!      @!!    @!!!:!    @!@!!@!   
!!@!!!    !!!@!!!!    @!!!    !!@!!!   !!!@!!!!  !!!  !@!  !!!  !!! !!@!!    !!!@!!!!  !@!  !!!  !!!@!!!!  !!!         @!!!     !!!     !!!!!:    !!@!@!    
!!:       !!:  !!!    !!:         !:!  !!:  !!!  !!:  !!:  !!!  :!!   !!:    !!:  !!!  !!:  !!!  !!:  !!!  !!:         !!:     !!:      !!:       !!: :!!   
:!:       :!:  !:!    :!:        !:!   :!:  !:!  :!:  :!:  !:!  :!:   !::    :!:  !:!  :!:  !:!  :!:  !:!   :!:        :!:    :!:       :!:       :!:  !:!  
 ::       ::   :::     ::    :::: ::   ::   :::   ::   ::   ::   ::: ::::    ::   :::   ::   ::  ::   :::   :: ::::     ::     :: ::::   :: ::::  ::   :::  
 :         :   : :     :     :: : :     :   : :  :    ::    :    :: :: :      :   : :  ::    :    :   : :  : :: : :     :     : :: : :  : :: ::    :   : :  
                                                                                                                                                            

========================================================== URL Analysis & Threat Detection v1.0 ==========================================================
        """);
    }

    // FILE READING & DATA GATHERING ----------------------------------------------------------------------------------------------
    // Populates homoglyph parralel-arrays (imposters to real standard ASCII chars) by reading homoglyphs.txt
    private void loadHomoglyphs() {
        try(InputStream inpS = getClass().getResourceAsStream("/homoglyphs.txt")){
            if(inpS != null){
                Scanner scnr = new Scanner(inpS);
                while(scnr.hasNextLine()){
                    String ln = scnr.nextLine().trim();
                    if(ln.startsWith("#") || ln.isEmpty()){
                        continue; // Skip blank spaces/ comments
                    }

                    // char[0] is standard ASCII, all else maps to it
                    for(int i=1;i<ln.length();i++){
                        homoglyphImposters.add(String.valueOf(line.charAt(i)));
                        homoglyphValues.add(String.valueOf(ln.charAt(0)));
                    }
                }
                System.out.println("[+] Successfully setup homoglyph database (" + homoglyphImposters.size() +"entries).");
            }
            else{
                System.out.println("[!] ERROR: Problem finding homoglyphs.txt: " + e.getMessage());
                return;
            }
        }
        catch(Exception err){
            System.out.println("[!] ERROR: Problem reading homoglyphs.txt: " + err.getMessage());
        }
    }

    // Reads files with whitelisted/blacklisted domains from disk
    private void loadStaticLists(){
        loadFromFile(WHITELISTED, staticWhitelist, "whitelist"); // Custom Trusted Domains - From file
        loadFromFile(BLACKLISTED, staticBlacklist, "blacklist");  // Custom Blacklisted Domains - From file
    }

    // Helper method to read files
    private void loadFromFile(String path, ArrayList<String> targetList, String label){
        File file = new File(path);
        if (!file.exists()) return; // File not found -> skip

        try (BufferedReader br = new BufferedReader(new FileReader(file))){
            String ln;
            int count = 0;
            while ((ln = br.readLine()) != null) {
                if (!ln.startsWith("#") && !ln.isEmpty()){
                    targetList.add(ln.trim().toLowerCase());
                    count++;
                }
            }
            System.out.println("[+] Loaded " + count + " entries into " + label + ".");
        }
        catch (IOException e){
            System.out.println("[!] ERROR: Problem reading " + label ": " +  err.getMessage());
        }
    }

    private ArrayList<String> getActiveBlacklist() {
        ArrayList<String> blacklist = new ArrayList<>(50_000); // Pre-size for large feed
        String url = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
 
        System.out.println("[*] Getting Live feed from https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt...");
        try {
            HttpClient clnt = HttpClient.newHttpClient();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();

            // Decode as UTF 8 String
            HttpResponse<String> res = clnt.send(req, HttpResponse.BodyHandlers.ofString());
 
            if (res.statusCode() == 200){ // OK - Parse
                Scanner scnr = new Scanner(res.body());
                while (sc.hasNextLine()){
                    String ln = sc.nextLine().trim().toLowerCase();
                    if (!ln.isEmpty() && !ln.startsWith("#")){
                        blacklist.add(ln);
                    }
                }
                System.out.println("[+] Added " + blacklist.size() + " malicious domains.");
            } else {
                System.err.println("[!] HTTP request failed :( " + res.statusCode());
            }
        } catch (Exception err) {
            System.err.println("[!] Error: problem getting blacklist: " + err.getMessage());
        }
        return blacklist; // Return populated (or empty -> failure) ArrayList
    }

    // URL ANALYSIS ----------------------------------------------------------------------------------------------

    public SeverityScore urlAnalyze(String url){
        ServerityScore rslt = new SeverityScore(url, "URL");

        // Normalize url and add https:// if needed
        if(url.contains("://")){
            String nUrl = url.toLowerCase().trim();
        }
        else{
            String nUrl = "https://" + url.toLowerCase().trim();
        }

        String domain = getDomain(nUrl);

        //-----1. Custom Whitelist check -> Skip all other steps if found-----
        if(staticWhitelist.contains(domain)){
            rslt.severityLevel = "WHITELISTED";
            rslt.score = 0;
            return rslt;
        }

        //-----2. Custom Blacklist check-----
        if(staticBlacklist.contains(domain)){
            rslt.redFlags.add(new RedFlag("Customly Blacklisted", "EXTREME", "Domain found in file of custom blacklists.", domain));
        }

        //-----3. Live Blacklist check (pulled from git repo)----
        if(phishingBlacklist.contains(domain)){
            rslt.redFlags.add(new Redflag("Live-Feed Threat", "EXTREME", "Domain found in a live file of active phishing domains.", domain));
        }

        //-----4. Target is an IP adress----
        if(Pattern.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*", domain)){
            rslt.redFlags.add(new RedFlag("IP Formatted Domain", "HIGH", "Inputed URL is a raw IP address instead of a recognised domain name.", domain));
        }

        //-----5. Address has a risky TLD----
        for(int i = 0; i < riskyTlds.length; i++){
            if(domain.endsWith(tld[i])){
                rslt.redFlags.add(new RedFlag("Uncommon/Potentially-Dangerous TLD", "MEDIUM", "This Top-Level domain is often abused by phishing websites", riskyTlds));
                break;
            }
        }

        //-----6. Impersonating a Trusted Brand/ 'typosquatting'----
        for(int i = 0; i < tlds.length; i++){
            if(domain.endsWith(trustedBrands[i])){
                String[] tokens = domain.split("\\.");
                if(!(tokens.length >= 2 && tokens[tokens.length - 2].equals(trustedBrands))){
                    rslt.redFlags.add(new RedFlag("Impersonating a Trusted Brand", "Extreme", "Trusted brand name found in extraordinary placement in URL.", domain));
                    break;
                }
            }
        }

        //-----7. Unicode Spoof/ 'Homoglyphs'-----
        ArrayList<String> foundGlyphs = new ArrayList<>();
        for(int i = 0; i < domain.length(); i++){
            char letterInQuestion = domain.charAt(i)
            for(int j = 0; j < homoglyphImposters.size(); j++){
                if(letterInQuestion == homoglyphImposters.get(j).charAt(0)){
                    foundGlyphs.add("Potential Homoglyph: '" + letterInQuestion + "' -> Normal ASCII Character: '" + homoglyphValues + "'");
                }
            }
        }
        if(!foundGlyphs.isEmpty()){
            String foundGlyphsStr = foundGlyphs.get(0);

            for(int i = 1; i < foundGlyphs.size(); i++){
                foundGlyphsStr = ", " + foundGlyphs.get(i);
            }
            rslt.redFlags.add(new RedFlag("Homoglyph", "MEDIUM", "Lookalike ASCII characters found: " + foundGlyphsStr, url))
        }

        //-----8. Contains A Common Fishing Keyword -----
        for(int i = 0; i < phishingKeywords.length; i++){
            if(nUrl.contains(phishingKeywords[i])){
                rslt.redFlags.add(new RedFlag("Phishing Keyword", "Low", "Suspicious/ Urgent Word in URL: " + phishingKeywords[i], url))
            }
        }

        //-----9. A lot of Subdomains -----
        // (more than 3)
        String[] tokens = domain.split("\\.");
        if(tokens.length > 3){
            rslt.redFlags.add(new RedFlag("Many Subdomains", "MEDIUM", "There Seems to be an excessive ammount of Subdomains [ "+ tokens.length + "]", url))
        }

        //-----10. Excessively Large URL -----
        if(url.length > 80){
            rslt.redFlags.add(new RedFlag("Large URL", "LOW", "The URL is suspiciously long (Possible Obfuscation)", url))
        }

        //-----11. No HTTPS -----
        if(nURL.startsWith("http://")){
            rslt.redFlags.add(new RedFlag("Insecure (HTTP)", "LOW", "The URL uses HTTP -> unencrypted transportation", "http://"));
        }

        //-----12. Suspicious number of digits in domain -----
        int numCount = 0;
        for(int i = 0; i < domain.length(); i++){
            if(Character.isDigit(domain.charAt(i))){
                numCount++;
            }
        }   
        // 6 is max number of digits
        if(numCount > 6){
            rslt.redFlags.add(new RedFlag("Many Domain Digits", "LOW", "The domain has a suspicious number of digit: (" + numCount + ") -> potentually auto-generated", domain));
        }

        calculateScore(rslt);
        return rslt;
    }



}
