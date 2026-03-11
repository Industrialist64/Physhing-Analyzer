import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

// Rating Scales

class RedFlag {
    public String type;
    public String threatLevel;
    public String description;
    public String evidence;

    public RedFlag(String type, String threatLevel, String description, String evidence){
        this.type = type;
        this.threatLevel = threatLevel;
        this.description = description;
        this.evidence = evidence;
    }
}

class SeverityScore{
    public String inputTarget;
    public String type;
    public int score = 0;
    public String severityLevel = "SAFE";
    public ArrayList<RedFlag> redFlags = new ArrayList<>();

    public SeverityScore(String inputTarget, String type) {
        this.inputTarget = inputTarget;
        this.type = type;
    }
}

// Main Application

public class PhyshingAnalyzer{

    private ArrayList<String> phishingBlacklist = new ArrayList()<>;
    private ArrayList<Char[]> homohlyphs = new ArrayList()<>;

    public PhyshingAnalyzer() {
        banner();
        System.out.println("[*] Initializing Analysis...");
        loadHomoglyphs();
        this.phishingBlacklist = fetchActiveBlacklist();
        System.out.println("[*] Program Ready ");
    }

    private void banner() {
        String bannerFinal = """
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
            """;
        System.out.println(bannerFinal);
    }

// Fetch Data
    private void loadHomoglyphs() {
        try(InputStream inpS = getClass().getResourceAsStream("/homoglyphs.txt")){
            if(inpS != null){
                Scanner scnr = new Scanner(inpS);
                while(scnr.hasNextLine()){
                    String ln = scnr.nextLine().trim();
                    if(ln.startsWith("#") || ln.isEmpty()){
                        continue;
                    }

                    // Note: Reference char is the char at 0 -- all else is imposters
                    Char[] singleCharWithImposters = new Char[ln.length()];
                    for(int i=0;i<ln.length();i++){
                        singleCharWithImposters[i] = ln.charAt(i);
                    }
                    homoglyphs.add(singleCharWithImposters);
                }
            }
            else{
                System.out.println("[!] ERROR: Problem finding homoglyphs.txt")
                return
            }
        }
    }
