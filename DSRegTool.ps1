<#
 
.SYNOPSIS
    DSRegTool V4.0 PowerShell script.

.DESCRIPTION
    Device Registration Troubleshooter Tool is a PowerShell script that troubleshoots device registration common issues.

.AUTHOR:
    Mohammad Zmaili

.EXAMPLE
    .\DSRegTool.ps1

    Enter (1) to troubleshoot Microsoft Entra Register

    Enter (2) to troubleshoot Microsoft Entra join device

    Enter (3) to troubleshoot Microsoft Entra hybrid join

    Enter (4) to verify Service Connection Point (SCP)

    Enter (5) to verify the health status of the device

    Enter (6) to Verify Primary Refresh Token (PRT)

    Enter (7) to collect the logs

    Enter (Q) to Quit


#>

Function DSRegToolStart{
    $ErrorActionPreference= 'silentlycontinue'
    Write-Host "DSRegTool 4.0 has started" -ForegroundColor Yellow
    $msg="Device Name : " + (Get-Childitem env:computername).value
    Write-Host $msg  -ForegroundColor Yellow
    $msg="User Account: " + (whoami) +", UPN: "+$global:UserUPN
    Write-Host $msg  -ForegroundColor Yellow
}

Function Test-DevRegConnectivity($Write){
    $ProxyTestFailed=$false
    $winInetProxy=$false
    $TestConnResult=@()
    If($Write){Write-Host}
    If($Write){Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow;  Write-Log -Message "Testing Internet Connectivity..."}
    $ErrorActionPreference= 'silentlycontinue'
    $global:TestFailed=$false

    $global:ProxyServer = checkProxy $Write
    If($Write){Write-Host}
    If($Write){Write-Host "Testing Device Registration Endpoints..." -ForegroundColor Yellow; Write-Log -Message "Testing Device Registration Endpoints..."}
    if ($global:ProxyServer -ne "NoProxy"){
        If($Write){Write-Host "Testing connection via winHTTP proxy..." -ForegroundColor Yellow; Write-Log -Message "Testing connection via winHTTP proxy..."}
        if ($global:login){
            $PSScript = "(Invoke-WebRequest -uri 'https://login.microsoftonline.com/common/oauth2' -UseBasicParsing).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'https://login.microsoftonline.com/common/oauth2' -UseBasicParsing -Proxy $global:ProxyServer).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to login.microsoftonline.com .............. Succeeded."}
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com .............. Succeeded."
        }else{
            $ProxyTestFailed=$true
        }

        if ($global:device){
            $PSScript = "(Invoke-WebRequest -uri 'https://device.login.microsoftonline.com/common/oauth2' -UseBasicParsing).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'https://device.login.microsoftonline.com/common/oauth2' -UseBasicParsing -Proxy $global:ProxyServer).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to device.login.microsoftonline.com ......  Succeeded."}
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com ......  Succeeded."
        }else{
            $ProxyTestFailed=$true
        }

        if ($global:enterprise){
            $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/$global:TenantName/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/$global:TenantName/discover?api-version=1.7' -UseBasicParsing -Proxy $global:ProxyServer -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to enterpriseregistration.windows.net ..... Succeeded."}
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ..... Succeeded."
        }else{
            $ProxyTestFailed=$true
        }
    }

    if (($global:ProxyServer -eq "NoProxy") -or ($ProxyTestFailed -eq $true)){
        if($ProxyTestFailed -eq $true){
            If($Write){Write-host "Connection failed via winHTTP, trying winInet..."; Write-Log -Message "Connection failed via winHTTP, trying winInet..." -Level WARN}
            If($Write){Write-Host ''}
        }else{
            If($Write){Write-host "Testing connection via winInet..." -ForegroundColor Yellow; Write-Log -Message "Testing connection via winInet..."}
            If($Write){Write-Host ''}
        }
        $PSScript = "(Invoke-WebRequest -uri 'https://login.microsoftonline.com/common/oauth2' -UseBasicParsing).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            $winInetProxy=$true
            If($Write){Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to login.microsoftonline.com .............. Succeeded."}
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com .............. Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red; Write-Log -Message "Connection to login.microsoftonline.com ................. failed." -Level ERROR}
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com ................. failed."
        }
        $PSScript = "(Invoke-WebRequest -uri 'https://device.login.microsoftonline.com/common/oauth2' -UseBasicParsing).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            $winInetProxy=$true
            If($Write){Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to device.login.microsoftonline.com ......  Succeeded."}
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com ......  Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red; Write-Log -Message "Connection to device.login.microsoftonline.com .......... failed." -Level ERROR}
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com .......... failed."
        }

        $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/$global:TenantName/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            $winInetProxy=$true
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to enterpriseregistration.windows.net ..... Succeeded."}
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ..... Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red; Write-Log -Message "Connection to enterpriseregistration.windows.net ........ failed." -Level ERROR}
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ........ failed."
        }
    }

    # If test failed
    if ($Write){
        if ($global:TestFailed){
            Write-Host ''
            Write-Host ''
            Write-Host "Test failed: device is not able to communicate with MS endpoints under system account" -ForegroundColor red
            Write-Log -Message "Test failed: device is not able to communicate with MS endpoints under system account" -Level ERROR
            Write-Host ''
            Write-Host "Recommended actions: " -ForegroundColor Yellow
            Write-Host "- Make sure that the device is able to communicate with the above MS endpoints successfully under the system account." -ForegroundColor Yellow
            Write-Host "- If the organization requires access to the internet via an outbound proxy, it is recommended to implement Web Proxy Auto-Discovery (WPAD)." -ForegroundColor Yellow
            Write-Host "- If you don't use WPAD, you can configure proxy settings with GPO by deploying WinHTTP Proxy Settings on your computers beginning with Windows 10 1709." -ForegroundColor Yellow
            Write-Host "- If the organization requires access to the internet via an authenticated outbound proxy, make sure that Windows 10 computers can successfully authenticate to the outbound proxy using the machine context." -ForegroundColor Yellow
            Write-Log -Message "Recommended actions:
            - Make sure that the device is able to communicate with the above MS endpoints successfully under the system account.
            - If the organization requires access to the internet via an outbound proxy, it is recommended to implement Web Proxy Auto-Discovery (WPAD).
            - If you don't use WPAD, you can configure proxy settings with GPO by deploying WinHTTP Proxy Settings on your computers beginning with Windows 10 1709.
            - If the organization requires access to the internet via an authenticated outbound proxy, make sure that Windows 10 computers can successfully authenticate to the outbound proxy using the machine context."
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host ''
            Write-Host "Test passed: Device is able to communicate with MS endpoints successfully under system context" -ForegroundColor Green
            Write-Log -Message "Test passed: Device is able to communicate with MS endpoints successfully under system context"
        }
    }
    If ($winInetProxy){$global:ProxyServer="winInet"}
    return $TestConnResult
}

Function Test-DevRegConnectivity-User($Write){
    $ErrorActionPreference= 'silentlycontinue'
    $global:TestFailed=$false
    $TestConnResult=@()
    If($Write){Write-Host}
    If($Write){Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow; Write-Log -Message "Testing Internet Connectivity..."}
    $InternetConn1=$true
    $InternetConn2=$true
    $InternetConn3=$true
    #$TestResult = (Test-NetConnection -ComputerName login.microsoftonline.com -Port 443).TcpTestSucceeded
    $TestResult = (Invoke-WebRequest -uri 'https://login.microsoftonline.com/common/oauth2' -UseBasicParsing).StatusCode
    if ($TestResult -eq 200){
        If($Write){Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green; Write-Log -Message "Connection to login.microsoftonline.com .............. Succeeded."}
        $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com .............. Succeeded."
    }else{
        If($Write){Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red; Write-Log -Message "Connection to login.microsoftonline.com ................. failed." -Level ERROR}
        $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com ................. failed."
        $InternetConn1=$false
        $global:TestFailed=$true
    }
    #$TestResult = (Test-NetConnection -ComputerName device.login.microsoftonline.com -Port 443).TcpTestSucceeded
    $TestResult = (Invoke-WebRequest -uri 'https://device.login.microsoftonline.com/common/oauth2' -UseBasicParsing).StatusCode
    if ($TestResult -eq 200){
        If($Write){Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green ;Write-Log -Message "Connection to device.login.microsoftonline.com ......  Succeeded."}
        $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com ......  Succeeded."
    }else{
        If($Write){Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red ;Write-Log -Message "Connection to device.login.microsoftonline.com .......... failed." -Level ERROR}
        $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com .......... failed."
        $InternetConn2=$false
        $global:TestFailed=$true
    }
    #$TestResult = (Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443).TcpTestSucceeded
    $TestResult = (Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/microsoft.com/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode
    if ($TestResult -eq 200){
        If($Write){Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green ;Write-Log -Message "Connection to enterpriseregistration.windows.net ..... Succeeded."}
        $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ..... Succeeded."
    }else{
        If($Write){Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red ;Write-Log -Message "Connection to enterpriseregistration.windows.net ........ failed." -Level ERROR}
        $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ........ failed."
        $InternetConn3=$false
        $global:TestFailed=$true
    }
    if ($Write){
        if ($global:TestFailed){
            Write-Host "Test failed: user is not able to communicate with MS endpoints" -ForegroundColor red ;Write-Log -Message "Test failed: user is not able to communicate with MS endpoints" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: make sure that the user is able to communicate with the above MS endpoints successfully" -ForegroundColor Yellow; Write-Log -Message "Recommended action: make sure that the user is able to communicate with the above MS endpoints successfully"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green; Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit   
       
        }else{
            Write-Host ''
            Write-Host "Test passed: User is able to communicate with MS endpoints successfully" -ForegroundColor Green ;Write-Log -Message "Test passed: User is able to communicate with MS endpoints successfully"
        }
    }
    return $TestConnResult
}

Function CheckePRT{
    Write-Host ''
    Write-Host "Checking Enterprise PRT..." -ForegroundColor Yellow
    Write-Log -Message "Checking Enterprise PRT..."
    $ePRT = $DSReg | Select-String EnterprisePrt | select-object -First 1
    $ePRT = ($ePRT.tostring() -split ":")[1].trim()
    if ($ePRT -eq 'YES'){
        $hostname = hostname
        Write-Host $hostname "device does have Enterprise PRT" -ForegroundColor Green
        Write-Log -Message "$hostname device does have Enterprise PRT"
    }else{
        $hostname = hostname
        Write-Host $hostname "device does NOT have Enterprise PRT" -ForegroundColor Yellow
        Write-Log -Message "$hostname device does NOT have Enterprise PRT" -Level WARN
    }
}

Function Write-Log{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [String] $Level = "INFO",

        [Parameter(Mandatory=$True)]
        [string] $Message,

        [Parameter(Mandatory=$False)]
        [string] $logfile = "DSRegTool.log"
    )
    if ($Message -eq " "){
        Add-Content $logfile -Value " " -ErrorAction SilentlyContinue
    }else{
        $Date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
        Add-Content $logfile -Value "[$date] [$Level] $Message" -ErrorAction SilentlyContinue
    }
}

Function PSasAdmin{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Test-DevRegApp-old{
    Write-Host ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    Write-Log -Message "Testing Device Registration Service..."
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green 
       Write-Log -Message "Test passed: Device Registration Service is enabled on the tenant"
    }else{
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red
        Write-Log -Message "Test failed: Device Registration Service is disabled on the tenant" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: enable Device Registration Service application on your tenant"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit                
    }
}

Function Test-DevRegApp{
    Write-Host ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    Write-Log -Message "Testing Device Registration Service..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if ($GraphResult.value.accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green 
       Write-Log -Message "Test passed: Device Registration Service is enabled on the tenant"
    }else{
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red
        Write-Log -Message "Test failed: Device Registration Service is disabled on the tenant" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: enable Device Registration Service application on your tenant"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit                
    }
}

Function SyncJoinCheck($Fallback){
    if($Fallback){
        Write-Host ''
        Write-Host ''
        Write-Host "Federated join flow failed, checking Sync join flow..."
        Write-Log -Message "Federated join flow failed, checking Sync join flow..."

        #Check OS version:
        Write-Host ''
        Write-Host "Testing OS version..." -ForegroundColor Yellow
        Write-Log -Message "Testing OS version..."
        $OSVersoin = ([environment]::OSVersion.Version).major
        $OSBuild = ([environment]::OSVersion.Version).Build
        if (($OSVersoin -ge 10) -and ($OSBuild -ge 17134)){#17134 build is 1803
            $OSVer = (([environment]::OSVersion).Version).ToString()
            Write-Host "Test passed: OS version supports fallback to sync join" -ForegroundColor Green
            Write-Log -Message "Test passed: OS version supports fallback to sync join"
        }else{
            # dsregcmd will not work.
            Write-Host "OS version does not support fallback to sync join, hence device registration will not complete" -ForegroundColor Red
            Write-Log -Message "OS version does not support fallback to sync join, hence device registration will not complete" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Fallback to sync join enabled by default on 1803 version and above" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Fallback to sync join enabled by default on 1803 version and above"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }

        #Checking FallbackToSyncJoin enablement
        Write-Host ''
        Write-Host "Checking fallback to sync join configuration..." -ForegroundColor Yellow
        Write-Log -Message "Checking fallback to sync join configuration..."
        $reg=Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ' -ErrorAction SilentlyContinue
        if ($reg.FallbackToSyncJoin -eq 0){
            Write-Host "Test failed: Fallback to sync join is disabled" -ForegroundColor Red
            Write-Log -Message "Test failed: Fallback to sync join is disabled" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Make sure that FallbackToSyncJoin is not disabled so that device fall back to sync join flow in case federated join flow failed" -ForegroundColor Yellow
            Write-Host "                    This can be done by removing 'FallbackToSyncJoin' registry value under 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Make sure that FallbackToSyncJoin is not disabled so that device fall back to sync join flow in case federated join flow failed`n                                 This can be done by removing 'FallbackToSyncJoin' registry value under 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Fallback to sync join is enabled" -ForegroundColor Green
            Write-Log -Message "Fallback to sync join is enabled"
        }
    }
    
    #Get device object GUID
    $DN=([adsisearcher]"(&(objectCategory=computer)(objectClass=computer)(cn=$env:COMPUTERNAME))").findall().path
    $OGuid = ([ADSI]$DN).ObjectGuid
    $ComputerGUID=(new-object guid(,$OGuid[0])).Guid
        
    #Checking userCert
    Write-Host ''
    Write-Host "Testing userCertificate attribute under AD computer object..." -ForegroundColor Yellow
    Write-Log -Message "Testing userCertificate attribute under AD computer object..."

    if($global:UserUPN.Length -ne 0){

        $ValidUserCertExist=$false
        $userCerts=([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().Properties.usercertificate
        $userCertCount=$userCerts.count
        if ($userCertCount -ge 1){
        Write-Host "AD computer object has $userCertCount certificate(s) under userCertificate attribute" -ForegroundColor Green
        Write-Log -Message "AD computer object has $userCertCount certificate(s) under userCertificate attribute"
        Write-Host ''
        Write-Host "Testing self-signed certificate validity..." -ForegroundColor Yellow
        Write-Log -Message "Testing self-signed certificate validity..."
            foreach ($userCert in $userCerts){
                $userCert=(new-object X509Certificate(,$userCert))
                $certSubject=($userCert.Subject.tostring() -split "CN=")[1].trim()
                If ($certSubject -eq $ComputerGUID){
                    $ValidUserCertExist=$true
                }
            }
        }else{
            #No userCert exist
            Write-Host "Test failed: There is no userCertificate under AD computer object" -ForegroundColor Red
            Write-Log -Message "Test failed: There is no userCertificate under AD computer object" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Make sure to start device registration process, and the device has permission to write self-signed certificate under AD computer object" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Make sure to start device registration process, and the device has permission to write self-signed certificate under AD computer object"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }
        if ($ValidUserCertExist){
            Write-Host "Test passed: AD computer object has a valid self-signed certificate" -ForegroundColor Green
            Write-Log -Message "Test passed: AD computer object has a valid self-signed certificate"
        }else{
            Write-Host "Test failed: There is no valid self-signed certificate under AD computer object userCertificate attribute" -ForegroundColor Red
            Write-Log -Message "Test failed: There is no valid self-signed certificate under AD computer object userCertificate attribute" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Make sure to start device registration process, and the device has permission to write self-signed certificate under AD computer object" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Make sure to start device registration process, and the device has permission to write self-signed certificate under AD computer object"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }
    }else{
        Write-Host "Test failed: signed in user is not a domain user, you should sign in with domain user to perform this test" -ForegroundColor Yellow
        Write-Log -Message "Test failed: signed in user is not a domain user, you should sign in with domain user to perform this test" -Level WARN
    }

    #Checking if device synced
    ConnecttoAzureAD
    Write-Host ''
    Write-Host "Testing if the device synced to Microsoft Entra ID..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device synced to Microsoft Entra ID..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$ComputerGUID'"
    $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
    $AADDevice=$GraphResult.Content | ConvertFrom-Json
    if($AADDevice.value.Count -ge 1){
        #The device existing in AAD:
        Write-Host "Test passed: the device object exists on Microsoft Entra ID" -ForegroundColor Green
        Write-Log -Message "Test passed: the device object exists on Microsoft Entra ID"
    }else{
        #Device does not exist:
        ###Reregister device to AAD
        Write-Host "Test failed: the device does not exist in your Microsoft Entra tenant" -ForegroundColor Red
        Write-Log -Message "Test failed: the device does not exist in your Microsoft Entra tenant" -Level ERROR
        $DeviceDN = ((([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().path).tostring() -split "LDAP://")[1].trim()
        Write-Host ''
        Write-Host "Recommended action: Make sure the device is in the sync scope, and it is successfully synced to Microsoft Entra ID by Microsoft Entra Connect." -ForegroundColor Yellow
        Write-Host "Device DN: $DeviceDN" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Make sure the device is in the sync scope, and it is successfully synced to Microsoft Entra ID by Microsoft Entra Connect.`n                                 Device DN: $DeviceDN"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }
}

Function CheckPRT{
    #Check OS version:
    Write-Host ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    Write-Log -Message "Testing OS version..."
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        $OSVer = (([environment]::OSVersion).Version).ToString()
        Write-Host "Test passed: device has current OS version ($OSVer)" -ForegroundColor Green
        Write-Log -Message "Test passed: device has current OS version ($OSVer)"
    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version" -ForegroundColor Red
        Write-Log -Message "The device has a Windows down-level OS version" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }

    #Check dsregcmd status.
    $DSReg = dsregcmd /status
    Write-Host ''
    Write-Host "Testing if the device is joined to the local domain..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device is joined to the local domain..."
    $DJ = $DSReg | Select-String DomainJoin
    $DJ = ($DJ.tostring() -split ":")[1].trim()
    if ($DJ -ne "YES"){
        $hostname = hostname
        Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow
        Write-Log -Message "$hostname device is NOT joined to the local domain"
    }else{
        #The device is joined to the local domain.
        $IS_DJ = $true
        $DomainName = $DSReg | Select-String DomainName 
        $DomainName =($DomainName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host $hostname "device is joined to the local domain:" $DomainName -ForegroundColor Yellow
        Write-Log -Message "$hostname device is joined to the local domain: $DomainName"
    }    

        #Checking if the device connected to AzureAD
    if ($DJ -eq 'YES'){
        #Check if the device is hybrid
        Write-Host ''
        Write-Host "Testing if the device is Microsoft Entra hybrid joined..." -ForegroundColor Yellow
        Write-Log -Message "Testing if the device is Microsoft Entra hybrid joined..."
        $AADJ = $DSReg | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            #The device is hybrid
            $hostname = hostname
            Write-Host $hostname "device is Microsoft Entra hybrid joined" -ForegroundColor Green
            Write-Log -Message "$hostname device is Microsoft Entra hybrid joined"
            #CheckPRT value
            Write-Host ''
            Write-Host "Testing Primary Refresh Token (PRT)..." -ForegroundColor Yellow
            Write-Log -Message "Testing Primary Refresh Token (PRT)..."
            $ADPRT = $DSReg | Select-String AzureAdPrt | select-object -First 1
            $ADPRT = ($ADPRT.tostring() -split ":")[1].Trim()
            if ($ADPRT -eq 'YES'){
                #PRT is available
                Write-Host "Test passed: Primary Refresh Token (PRT) is available on this device for the logged on user" -ForegroundColor Green
                Write-Log -Message "Test passed: Primary Refresh Token (PRT) is available on this device for the logged on user"
                CheckePRT
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
            }else{
                #PRT not available
                Write-Host "Test failed: Primary Refresh Token (PRT) is not available. Hence SSO will not work, and the device may be blocked if you have a device-based Conditional Access Policy" -ForegroundColor Red
                Write-Log -Message "Test failed: Primary Refresh Token (PRT) is not available. Hence SSO will not work, and the device may be blocked if you have a device-based Conditional Access Policy" -Level ERROR
                Write-Host ''
                Write-Host "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support"
                CheckePRT
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit
            }
        }else{
            $hostname = hostname
            Write-Host $hostname "device is NOT Microsoft Entra hybrid joined" -ForegroundColor Yellow
            Write-Log -Message "$hostname device is NOT Microsoft Entra hybrid joined"
            #Check WPJ
            Write-Host ''
            Write-Host "Testing if the device is Microsoft Entra Registered..." -ForegroundColor Yellow
            Write-Log -Message "Testing if the device is Microsoft Entra Registered..."
            $WPJ = $DSReg | Select-String WorkplaceJoined | Select-Object -First 1
            $WPJ = ($WPJ.tostring() -split ":")[1].trim()
            if ($WPJ -eq 'YES'){
                $hostname = hostname
                Write-Host $hostname "device is Microsoft Entra Registered" -ForegroundColor Green
                Write-Log -Message "$hostname device is Microsoft Entra Registered"
                #Device is WPJ, check the registry
                Write-Host ''
                Write-Host "Testing Primary Refresh Token (PRT) registry value..." -ForegroundColor Yellow
                if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
                    Write-Host "Test passed: Primary Refresh Token (PRT) registry value exists for the logged on user" -ForegroundColor Green
                    Write-Log -Message "Test passed: Primary Refresh Token (PRT) registry value exists for the logged on user"
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                    Write-Host ''
                    }else{
                    Write-Host "Test failed: Primary Refresh Token (PRT) registry value does not exist for the logged on user" -ForegroundColor Red
                    Write-Log -Message "Test failed: Primary Refresh Token (PRT) registry value does not exist for the logged on user" -Level ERROR
                    Write-Host ''
                    Write-Host "Recommended action: Disconnect the device from Microsoft Entra ID form 'settings > Accounts > Access work or school' and then connect it again to Microsoft Entra ID" -ForegroundColor Yellow
                    Write-Log -Message "Recommended action: Disconnect the device from Microsoft Entra ID form 'settings > Accounts > Access work or school' and then connect it again to Microsoft Entra ID"
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                    Write-Host ''
                    exit                
                }
            }else{
                $hostname = hostname
                Write-Host $hostname "device is NOT Microsoft Entra Registered" -ForegroundColor Yellow
                Write-Log -Message "$hostname device is NOT Microsoft Entra Registered"
                Write-Host ''
                Write-Host "Test failed:" $hostname "device is NOT connected to Microsoft Entra ID, hence PRT does not exist" -ForegroundColor Red
                Write-Log -Message "Test failed: $hostname device is NOT connected to Microsoft Entra ID, hence PRT does not exist" -Level ERROR
                Write-Host ''
                Write-Host "Recommended action: make sure the device is connected to Microsoft Entra ID to get Primary Refresh Token (PRT)" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: make sure the device is connected to Microsoft Entra ID to get Primary Refresh Token (PRT)"
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit        
            }
        }
    }else{
        #Check if the device AADJ
        Write-Host ''
        Write-Host "Testing if the device is Microsoft Entra join..." -ForegroundColor Yellow
        Write-Log -Message "Testing if the device is Microsoft Entra join..."
        $AADJ = $DSReg | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            #The device AADJ
            $hostname = hostname
            Write-Host $hostname "device is Microsoft Entra join" -ForegroundColor Green
            Write-Log -Message "$hostname device is Microsoft Entra join"
            #CheckPRT value
            Write-Host ''
            Write-Host "Testing Primary Refresh Token (PRT)..." -ForegroundColor Yellow
            Write-Log -Message "Testing Primary Refresh Token (PRT)..."
            $ADPRT = $DSReg | Select-String AzureAdPrt | select-object -First 1
            $ADPRT = ($ADPRT.tostring() -split ":")[1].Trim()
            if ($ADPRT -eq 'YES'){
                #PRT is available
                Write-Host "Test passed: Primary Refresh Token (PRT) is available on this device for the logged on user" -ForegroundColor Green
                Write-Log -Message "Test passed: Primary Refresh Token (PRT) is available on this device for the logged on user" 
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
            }else{
                #PRT not available
                Write-Host "Test failed: Primary Refresh Token (PRT) is not available. Hence SSO will not work, and the device may be blocked if you have a device-based Conditional Access Policy" -ForegroundColor Red
                Write-Log -Message "Test failed: Primary Refresh Token (PRT) is not available. Hence SSO will not work, and the device may be blocked if you have a device-based Conditional Access Policy"
                Write-Host ''
                Write-Host "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support"
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit
            }
        }else{
            $hostname = hostname
            Write-Host $hostname "device is NOT Microsoft Entra join" -ForegroundColor Yellow
            Write-Log -Message "$hostname device is NOT Microsoft Entra join"
            #Check WPJ
            Write-Host ''
            Write-Host "Testing if the device is Microsoft Entra Registered..." -ForegroundColor Yellow
            Write-Log -Message "Testing if the device is Microsoft Entra Registered..."
            $WPJ = $DSReg | Select-String WorkplaceJoined
            $WPJ = ($WPJ.tostring() -split ":")[1].trim()
            if ($WPJ -eq 'YES'){
                #Device is WPJ, check the registry
                $hostname = hostname
                Write-Host $hostname "device is Microsoft Entra Registered" -ForegroundColor Green
                Write-Log -Message "$hostname device is Microsoft Entra Registered"
                #check registry
                Write-Host ''
                Write-Host "Testing Primary Refresh Token (PRT) registry value..." -ForegroundColor Yellow
                Write-Log -Message "Testing Primary Refresh Token (PRT) registry value..."
                if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
                    Write-Host "Test passed: Primary Refresh Token (PRT) registry value exists for the logged on user" -ForegroundColor Green
                    Write-Log -Message "Test passed: Primary Refresh Token (PRT) registry value exists for the logged on user"
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                }else{
                    Write-Host "Test failed: Primary Refresh Token (PRT) registry value does not exist for the logged on user" -ForegroundColor Red
                    Write-Log -Message "Test failed: Primary Refresh Token (PRT) registry value does not exist for the logged on user" -Level ERROR
                    Write-Host ''
                    Write-Host "Recommended action: Disconnect the device from Microsoft Entra ID form 'settings > Accounts > Access work or school' and then connect it again to Microsoft Entra ID" -ForegroundColor Yellow
                    Write-Log -Message "Recommended action: Disconnect the device from Microsoft Entra ID form 'settings > Accounts > Access work or school' and then connect it again to Microsoft Entra ID"
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                    Write-Host ''
                    exit                
                }
            }else{
                $hostname = hostname
                Write-Host $hostname "device is NOT Microsoft Entra Registered" -ForegroundColor Yellow
                Write-Log -Message "$hostname device is NOT Microsoft Entra Registered"
                Write-Host "Test failed:" $hostname "device is NOT connected to Microsoft Entra ID, hence PRT does not exist" -ForegroundColor Red
                Write-Log -Message "Test failed: $hostname device is NOT connected to Microsoft Entra ID, hence PRT does not exist"
                Write-Host ''
                Write-Host "Recommended action: make sure the device is connected to Microsoft Entra ID to get Azure PRT" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: make sure the device is connected to Microsoft Entra ID to get Azure PRT"
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit        
            }
        }
    }
}

Function checkProxy($Write){
    # Check Proxy settings
    If($Write){Write-Host "Checking winHTTP proxy settings..." -ForegroundColor Yellow; Write-Log -Message "Checking winHTTP proxy settings..."}
    $global:ProxyServer="NoProxy"
    $winHTTP = netsh winhttp show proxy
    $Proxy = $winHTTP | Select-String server
    $global:ProxyServer=$Proxy.ToString().TrimStart("Proxy Server(s) :  ")
    $global:Bypass = $winHTTP | Select-String Bypass
    $global:Bypass=$global:Bypass.ToString().TrimStart("Bypass List     :  ")

    if ($global:ProxyServer -eq "Direct access (no proxy server)."){
        $global:ProxyServer="NoProxy"
        If($Write){Write-Host "Access Type : DIRECT"; Write-Log -Message "Access Type : DIRECT"}
    }

    if ( ($global:ProxyServer -ne "NoProxy") -and (-not($global:ProxyServer.StartsWith("http://")))){
        If($Write){Write-Host "      Access Type : PROXY"; Write-Log -Message "      Access Type : PROXY"}
        If($Write){Write-Host "Proxy Server List :" $global:ProxyServer; Write-Log -Message "Proxy Server List : $global:ProxyServer"}
        If($Write){Write-Host "Proxy Bypass List :" $global:Bypass; Write-Log -Message "Proxy Bypass List : $global:Bypass"}
        $global:ProxyServer = "http://" + $global:ProxyServer
    }

    $global:login= $global:Bypass.Contains("*.microsoftonline.com") -or $global:Bypass.Contains("login.microsoftonline.com")

    $global:device= $global:Bypass.Contains("*.microsoftonline.com") -or $global:Bypass.Contains("*.login.microsoftonline.com") -or $global:Bypass.Contains("device.login.microsoftonline.com")

    $global:enterprise= $global:Bypass.Contains("*.windows.net") -or $global:Bypass.Contains("enterpriseregistration.windows.net")

    #CheckwinInet proxy
    If($Write){Write-Host ''}
    If($Write){Write-Host "Checking winInet proxy settings..." -ForegroundColor Yellow; Write-Log -Message "Checking winInet proxy settings..."}
    $winInet=RunPScript -PSScript "Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'"
    if($winInet.ProxyEnable){If($Write){Write-Host "    Proxy Enabled : Yes"; Write-Log -Message "    Proxy Enabled : Yes"}}else{If($Write){Write-Host "    Proxy Enabled : No";Write-Log -Message "    Proxy Enabled : No"}}
    $winInetProxy="Proxy Server List : "+$winInet.ProxyServer
    If($Write){Write-Host $winInetProxy;Write-Log -Message $winInetProxy}
    $winInetBypass="Proxy Bypass List : "+$winInet.ProxyOverride
    If($Write){Write-Host $winInetBypass; Write-Log -Message $winInetBypass}
    $winInetAutoConfigURL="    AutoConfigURL : "+$winInet.AutoConfigURL
    If($Write){Write-Host $winInetAutoConfigURL;Write-Log -Message $winInetAutoConfigURL}

    return $global:ProxyServer
}

Function WPJTS{
    #Check OS version:
    Write-Host ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    Write-Log -Message "Testing OS version..."
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        $OSVer = (([environment]::OSVersion).Version).ToString()
        Write-Host "Test passed: device has current OS version ($OSVer)" -ForegroundColor Green
        Write-Log -Message "Test passed: device has current OS version ($OSVer)"
    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version" -ForegroundColor Red
        Write-Log -Message "The device has a Windows down-level OS version"
        Write-Host ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }
    #Check dsregcmd status.
    $DSReg = dsregcmd /status
    $hostname=hostname
    #Checking if the device connected to AzureAD
    Write-Host ''
    Write-Host "Testing if the device is Microsoft Entra Registered..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device is Microsoft Entra Registered..."
    $WPJ = $DSReg | Select-String WorkplaceJoined | Select-Object -First 1
    $WPJ = ($WPJ.tostring() -split ":")[1].trim()
    if ($WPJ -ne "YES"){
        #The device is not connected to AAD:
        ### perform WPJ (all other tests should be here)
        Write-Host "Test failed:" $hostname "device is NOT connected to Microsoft Entra ID as Microsoft Entra Registered device" -ForegroundColor Red
        Write-Log -Message "Test failed: $hostname device is NOT connected to Microsoft Entra ID as Microsoft Entra Registered device"
    
        #Checking Internet connectivity
        Test-DevRegConnectivity-User $true | out-null

        ConnecttoAzureAD
        Test-DevRegApp
        Write-Host ''
        Write-Host ''
        Write-Host "All tests completed successfully. You can start registering your device to Microsoft Entra ID." -ForegroundColor Green
        Write-Log -Message "All tests completed successfully. You can start registering your device to Microsoft Entra ID."
        Write-Host ''
        Write-Host ''
        exit
    }else{
        #The device is WPJ join
        $TenantName = $DSReg | Select-String WorkplaceTenantName
        $TenantName =($TenantName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host "Test passed:" $hostname "device is connected to Microsoft Entra tenant:" $TenantName "as Microsoft Entra Registered device" -ForegroundColor Green
        Write-Log -Message "Test passed: $hostname device is connected to Microsoft Entra tenant: $TenantName as Microsoft Entra Registered device"
    }

    #Check the device status on AAD:
    $DID = $DSReg | Select-String WorkplaceDeviceId
    $DID = ($DID.ToString() -split ":")[1].Trim()
    CheckDeviceHealth $DID $true

    Write-Host ''
    Write-Host ''
    Write-Host "The device is connected to Microsoft Entra ID as Microsoft Entra Registered device, and it is in healthy state." -ForegroundColor Green
    Write-Log -Message "The device is connected to Microsoft Entra ID as Microsoft Entra Registered device, and it is in healthy state."
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''
}#end WPJTS

Function AADJ{
    <##Check PSAdmin
    Write-Host ''
    Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow 
    Write-Log -Message "Testing if PowerShell running with elevated privileges..."
    if (PSasAdmin){
        # PS running as admin.
        Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green
        Write-Log -Message "PowerShell is running with elevated privileges"
    }else{
        Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red
        Write-Log -Message "PowerShell is NOT running with elevated privileges" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: This test needs to be running with elevated privileges" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: This test needs to be running with elevated privileges"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }#>
    #Check OS version:
    Write-Host ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    Write-Log -Message "Testing OS version..."
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        $OSVer = (([environment]::OSVersion).Version).ToString()
        Write-Host "Test passed: device has current OS version ($OSVer)" -ForegroundColor Green
        Write-Log -Message "Test passed: device has current OS version ($OSVer)"
    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
        Write-Log -Message "The device has a Windows down-level OS version." -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above."
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }
    #Check dsregcmd status.
    $DSReg = dsregcmd /status
    Write-Host ''
    Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device joined to the local domain..."
    $DJ = $DSReg | Select-String DomainJoin
    $DJ = ($DJ.tostring() -split ":")[1].trim()
    if ($DJ -ne "YES"){
        $hostname = hostname
        Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow
        Write-Log -Message "device is NOT joined to the local domain"
    }else{
        #The device is joined to the local domain.
        $DomainName = $DSReg | Select-String DomainName 
        $DomainName =($DomainName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host $hostname "device is joined to the local domain:" $DomainName -ForegroundColor Yellow
        Write-Log -Message "$hostname device is joined to the local domain: $DomainName"
        Write-Host ''
        Write-Host "Recommended action: The selected option runs for AADJ devices. To troubleshoot hybrid devices, re-run the script and select option '3'." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: The selected option runs for AADJ devices. To troubleshoot hybrid devices, re-run the script and select option '3'."
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }    

    #Checking if the device connected to AzureAD
    ''
    Write-Host "Testing if the device is joined to Microsoft Entra ID..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device is joined to Microsoft Entra ID..."
    $AADJ = $DSReg | Select-String AzureAdJoined
    $AADJ = ($AADJ.tostring() -split ":")[1].trim()
    if ($AADJ -ne "YES"){
        #The device is not connected to AAD:
        ### perform AADJ (all other tests should be here)
        Write-Host "Test failed:" $hostname "device is NOT connected to Microsoft Entra ID" -ForegroundColor Red
        Write-Log -Message "Test failed: $hostname device is NOT connected to Microsoft Entra ID"

        <##Checking if the user is bulitin admin
        Write-Host ''
        Write-Host "Testing if you signed in user is a Built-in Administrator account..." -ForegroundColor Yellow
        Write-Log -Message "Testing if you signed in user is a Built-in Administrator account..."
        $BAdmin=(Get-LocalUser | where{$_.SID -like "*-500"}).name
        $LUser=$env:username
        if ($BAdmin -eq $LUser){
            Write-Host "Test failed: you signed in using the built-in Administrator account" -ForegroundColor Red
            Write-Log -Message "Test failed: you signed in using the built-in Administrator account" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: create a different local account before you use Azure Active Directory join to finish the setup." -ForegroundColor Yellow
            Write-Log -Message "Recommended action: create a different local account before you use Azure Active Directory join to finish the setup."
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit        
        }else{
            Write-Host "Test passed: you are not signed in using the built-in Administrator account" -ForegroundColor Green
            Write-Log -Message "Test passed: you are not signed in using the built-in Administrator account"
        }#>
        #Checking if the signed in user is a local admin
        Write-Host ''
        Write-Host "Testing if the signed in user has local admin permissions..." -ForegroundColor Yellow
        Write-Log -Message "Testing if the signed in user has local admin permissions..."
        $LocalAdminGroup=(whoami /groups | Select-String 'S-1-5-32-544')
        #if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        if ($LocalAdminGroup){
            Write-Host "Test passed: the signed in user has local admin permissions" -ForegroundColor Green
            Write-Log -Message "Test passed: the signed in user has local admin permissions"
        }else{
            Write-Host "Test failed: the signed in user does NOT have local admin permissions" -ForegroundColor Red
            Write-Log -Message "Test failed: the signed in user does NOT have local admin permissions" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: sign in with a user that has local admin permissions before you start joining the device to Microsoft Entra ID to finish the setup" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: sign in with a user that has local admin permissions before you start joining the device to Microsoft Entra ID to finish the setup"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }
    
        #Checking Internet connectivity
        Test-DevRegConnectivity-User $true | out-null

        #CheckMSOnline
        ConnecttoAzureAD
        Test-DevRegApp
        Write-Host ''
        Write-Host ''
        Write-Host "All tests completed successfully. You can start joining your device to Microsoft Entra ID." -ForegroundColor Green
        Write-Log -Message "All tests completed successfully. You can start joining your device to Microsoft Entra ID."
        Write-Host ''
        Write-Host ''
        exit
    }else{
        #The device is Microsoft Entra join
        $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
        $TenantName =($TenantName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host "Test passed:" $hostname "device is joined to Microsoft Entra tenant:" $TenantName -ForegroundColor Green
        Write-Log -Message "Test passed: $hostname device is joined to Microsoft Entra tenant: $TenantName"
    }

    #CheckMSOnline

    #Check the device status on AAD:
    $DID = $DSReg | Select-String DeviceId  | Select-Object -first 1
    $DID = ($DID.ToString() -split ":")[1].Trim()
    CheckDeviceHealth $DID $true

    Write-Host ''
    Write-Host ''
    Write-Host "The device is connected to Microsoft Entra ID as Microsoft Entra joined device, and it is in healthy state" -ForegroundColor Green
    Write-Log -Message "The device is connected to Microsoft Entra ID as Microsoft Entra joined device, and it is in healthy state"
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''    
    #end AADJ
}

Function VerifySCP{
    #Check client-side registry setting for SCP
    $SCPClient=$false
    Write-Host ''
    Write-Host "Testing client-side registry setting for SCP..." -ForegroundColor Yellow
    Write-Log -Message "Testing client-side registry setting for SCP..."
    $Reg=Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
    if (((($Reg.TenantId).Length) -eq 0) -AND ((($Reg.TenantName).Length) -eq 0)) {
        Write-Host "Client-side registry setting for SCP is not configured" -ForegroundColor Yellow
        Write-Log -Message "Client-side registry setting for SCP is not configured"
    }else{
        $SCPClient=$true
        Write-Host "Client-side registry setting for SCP is configured as the following:" -ForegroundColor Green
        Write-Log -Message "Client-side registry setting for SCP is configured as the following:"
        Write-Host "TenantId:" $Reg.TenantId
        $Reg_TenantId="TenantId:"+ $Reg.TenantId
        Write-Log -Message $Reg_TenantId
        $global:TenantName = $Reg.TenantName
        Write-Host "TenantName:" $Reg.TenantName
        $Reg_TenantName="TenantName:"+ $Reg.TenantName
        Write-Log -Message $Reg_TenantName
        #Check client-side SCP info
        Write-Host ''
        Write-Host "Testing client-side registry configuration..." -ForegroundColor Yellow
        Write-Log -Message "Testing client-side registry configuration..."
        
        #CheckMSOnline
        #Checking tenant name
        Write-Host ''
        Write-Host "Testing Tenant Name..." -ForegroundColor Yellow
        Write-Log -Message "Testing Tenant Name..."
        $RegTenantName=$Reg.TenantName
        $InvokeResult=""
        $InvokeResult=(Invoke-WebRequest -Uri "https://login.microsoftonline.com/$RegTenantName/.well-known/openid-configuration" -UseBasicParsing).content | ConvertFrom-Json
        if($InvokeResult){
            $TenantID=($InvokeResult.issuer.tostring() -split "https://sts.windows.net/")[1].trim()
            $TenantID=($TenantID.tostring() -split "/")[0].trim()
            Write-Host "Tenant Name is configured correctly" -ForegroundColor Green
            Write-Log -Message "Tenant Name is configured correctly"
            Write-Host ''
            Write-Host "Testing Tenant ID..." -ForegroundColor Yellow
            Write-Log -Message "Testing Tenant ID..."
            if ($TenantID -eq $Reg.TenantId){
                Write-Host "Tenant ID is configured correctly" -ForegroundColor Green
                Write-Log -Message "Tenant ID is configured correctly"
            }else{
                Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red
                Write-Log -Message "Test failed: Tenant ID is not configured correctly" -Level ERROR
                Write-Host ''
                Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in registry." -ForegroundColor Yellow
                Write-Host "Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: Make sure the Tenant ID is configured correctly in registry `n                                 Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD"
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit
            }
        }else{
            Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red
            Write-Log -Message "Test failed: Tenant Name is not configured correctly" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in registry" -ForegroundColor Yellow
            Write-Host "Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Make sure the Tenant Name is configured correctly in registry `n                                 Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }
    }

    #Check connectivity to DC
    $global:DCTestPerformed=$true
    Write-Host ''
    Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
    Write-Log -Message "Testing Domain Controller connectivity..."
    $DCName=""
    $DCTest=nltest /dsgetdc:
    $DCName = $DCTest | Select-String DC | Select-Object -first 1
    $DCName =($DCName.tostring() -split "DC: \\")[1].trim()
    if (($DCName.length) -eq 0){
        Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red
        Write-Log -Message "Test failed: connection to Domain Controller failed" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Make sure that the device has a line of sight connection to the Domain controller" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Make sure that the device has a line of sight connection to the Domain controller"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit        
    }else{
        Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green
        Write-Log -Message "Test passed: connection to Domain Controller succeeded"
    }


    #Check SCP
    if ($SCPClient -eq $false){
        Write-Host ''
        Write-Host "Checking Service Connection Point (SCP)..." -ForegroundColor Yellow
        Write-Log -Message "Checking Service Connection Point (SCP)..."
        $Root = [ADSI]"LDAP://RootDSE"
        $ConfigurationName = $Root.rootDomainNamingContext
        $scp = New-Object System.DirectoryServices.DirectoryEntry;
        $scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
        if ($scp.Keywords -ne $null){
            Write-Host "Service Connection Point (SCP) is configured as following:" -ForegroundColor Green
            Write-Log -Message "Service Connection Point (SCP) is configured as following:"
            $scp.Keywords
            Write-Log -Message $scp.Keywords
            #check SCP
            Write-Host ''
            Write-Host "Testing Service Connection Point (SCP) configuration..." -ForegroundColor Yellow
            Write-Log -Message "Testing Service Connection Point (SCP) configuration..."
            $TID = $scp.Keywords | Select-String azureADId
            $TID = ($TID.tostring() -split ":")[1].trim()
            
            $TN = $scp.Keywords | Select-String azureADName
            $TN = ($TN.tostring() -split ":")[1].trim()
            $global:TenantName = $TN

            #CheckMSOnline
            #Checking tenant name
            Write-Host ''
            Write-Host "Testing Tenant Name..." -ForegroundColor Yellow
            Write-Log -Message "Testing Tenant Name..."
            $InvokeResult=""
            $InvokeResult=(Invoke-WebRequest -Uri "https://login.microsoftonline.com/$TN/.well-known/openid-configuration" -UseBasicParsing).content | ConvertFrom-Json
            if($InvokeResult){
                $TenantID=($InvokeResult.issuer.tostring() -split "https://sts.windows.net/")[1].trim()
                $TenantID=($TenantID.tostring() -split "/")[0].trim()
                Write-Host "Test passed: Tenant Name is configured correctly" -ForegroundColor Green
                Write-Log -Message "Test passed: Tenant Name is configured correctly"
                Write-Host ''
                Write-Host "Testing Tenant ID..." -ForegroundColor Yellow
                Write-Log -Message "Testing Tenant ID..."
                if ($TenantID -eq $TID){
                    Write-Host "Test passed: Tenant ID is configured correctly" -ForegroundColor Green
                    Write-Log -Message "Test passed: Tenant ID is configured correctly"
                }else{
                    Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red
                    Write-Log -Message "Test failed: Tenant ID is not configured correctly" -Level ERROR
                    Write-Host ''
                    Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in SCP." -ForegroundColor Yellow
                    Write-Log -Message "Recommended action: Make sure the Tenant ID is configured correctly in SCP."
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                    Write-Host ''
                    exit
                }

            }else{
                Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red
                Write-Log -Message "Test failed: Tenant Name is not configured correctly" -Level ERROR
                Write-Host ''
                Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in SCP." -ForegroundColor Yellow
                Write-Log -Message "Recommended action: Make sure the Tenant Name is configured correctly in SCP."
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit
            }

        }else{
            Write-Host "Test failed: Service Connection Point is not configured in your forest" -ForegroundColor red
            Write-Log -Message "Test failed: Service Connection Point is not configured in your forest" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: make sure to configure SCP in your forest" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: make sure to configure SCP in your forest"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit

        }
    }
}

#Log Collection functions
Function getwinHTTPinInet{
    #ExportwinHTTP
    netsh winhttp show proxy | Out-file "$global:LogsPath\winHTTP.txt"
    Write-Log -Message "winHTTP.txt exported" -logfile "$global:LogsPath\Log.log"
    #ExportwinInet proxy
    $winInetOutput=""
    $winInet=RunPScript -PSScript "Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'"
    $winInet | Out-File "$global:LogsPath\winInet-system-regkey.txt"
    Write-Log -Message "winInet-system-regkey.txt exported" -logfile "$global:LogsPath\Log.log"
    if($winInet.ProxyEnable){$winInetOutput+= "    Proxy Enabled : Yes`n"}else{$winInetOutput+= "    Proxy Enabled : No`n"}
    $winInetProxy="Proxy Server List : "+$winInet.ProxyServer
    $winInetOutput+= $winInetProxy+"`n"
    $winInetBypass="Proxy Bypass List : "+$winInet.ProxyOverride
    $winInetOutput+=$winInetBypass+"`n"
    $winInetAutoConfigURL="    AutoConfigURL : "+$winInet.AutoConfigURL
    $winInetOutput+= $winInetAutoConfigURL
    $winInetOutput | Out-file "$global:LogsPath\winInet-system.txt"
    Write-Log -Message "winInet-system.txt exported" -logfile "$global:LogsPath\Log.log"

    #winInet_User
    $winInetOutput=""
    $winInet=Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $winInet | Out-File "$global:LogsPath\winInet-user-regkey.txt"
    Write-Log -Message "winInet-user-regkey.txt exported" -logfile "$global:LogsPath\Log.log"
    if($winInet.ProxyEnable){$winInetOutput+= "    Proxy Enabled : Yes`n"}else{$winInetOutput+= "    Proxy Enabled : No`n"}
    $winInetProxy="Proxy Server List : "+$winInet.ProxyServer
    $winInetOutput+= $winInetProxy+"`n"
    $winInetBypass="Proxy Bypass List : "+$winInet.ProxyOverride
    $winInetOutput+=$winInetBypass+"`n"
    $winInetAutoConfigURL="    AutoConfigURL : "+$winInet.AutoConfigURL
    $winInetOutput+= $winInetAutoConfigURL
    $winInetOutput | Out-file "$global:LogsPath\winInet-user.txt"
    Write-Log -Message "winInet-user.txt exported" -logfile "$global:LogsPath\Log.log"
}

Function getSCP{
    $ErrorActionPreference= 'silentlycontinue'
    #Check SCP-config-partition
    $Root = [ADSI]"LDAP://RootDSE"
    $ConfigurationName = $Root.rootDomainNamingContext
    if (($ConfigurationName.length) -eq 0){
        Add-Content "$global:LogsPath\SCP-config-partition.txt" -Value "Not able to read Service Connection Point from configuration partition" -ErrorAction SilentlyContinue
    }else{
        $scp = New-Object System.DirectoryServices.DirectoryEntry;
        $scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
        if ($scp.Keywords -ne $null){
            Add-Content "$global:LogsPath\SCP-config-partition.txt" -Value $scp.Keywords -ErrorAction SilentlyContinue
            $TN = $scp.Keywords | Select-String azureADName
            $TN = ($TN.tostring() -split ":")[1].trim()
            $global:TenantName = $TN
        }else{
            Add-Content "$global:LogsPath\SCP-config-partition.txt" -Value "Service Connection Point is not configured in configurationconfiguration partition" -ErrorAction SilentlyContinue
        }
    }
    #SCP-client-side
    $Reg=Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
    if (((($Reg.TenantId).Length) -eq 0) -AND ((($Reg.TenantName).Length) -eq 0)) {
       Add-Content "$global:LogsPath\SCP-client-side.txt" -Value "Client-side registry setting for SCP is not configured" -ErrorAction SilentlyContinue
    }else{
        #$SCPClient=$true
        $SCPclientside= "Client-side registry setting for SCP is configured as the following:`n"
        $SCPclientside+=$Reg_TenantId="TenantId:"+ $Reg.TenantId+"`n"
        $SCPclientside+=$Reg_TenantName="TenantName:"+ $Reg.TenantName
        Add-Content "$global:LogsPath\SCP-client-side.txt" -Value $SCPclientside -ErrorAction SilentlyContinue
        $global:TenantName=$Reg.TenantName
    }
}

Function ExportEventViewerLogs ($EventViewerLogs,$ExportPath){
    ForEach ($EventViewerLog in $EventViewerLogs){		$EventViewerLogAfter = [regex]::Replace($EventViewerLog,"/","-")        $EventViewerLogAfter=($EventViewerLogAfter -split "Microsoft-Windows-")[1].trim()		$ExportedFileName = $ExportPath +"\"+ $EventViewerLogAfter+".evtx"
        (New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ExportLogAndMessages($EventViewerLog,'LogName','*',$ExportedFileName)        Write-Log -Message "$EventViewerLogAfter event log exported successfully" -logfile "$global:LogsPath\Log.log"    }
}

Function EnableDebugEvents ($DbgEvents){    ForEach ($evt in $DbgEvents){        $Log=New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt        $Log.IsEnabled =$false        $Log.SaveChanges()        $Log.IsEnabled =$true        $Log.SaveChanges()        Write-Log -Message "$evt enabled" -logfile "$global:LogsPath\Log.log"    }}

Function DisableDebugEvents ($DbgEvents){    ForEach ($evt in $DbgEvents){	    $Log = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt		$Log.IsEnabled = $false		$Log.SaveChanges()        Write-Log -Message "$evt disabled" -logfile "$global:LogsPath\Log.log"    }
}

Function CollectLogAADExt($RunLogs){
    Push-Location $global:LogsPath    ForEach ($RunLog in $RunLogs){		cmd.exe /c $RunLog        Write-Log -Message $RunLog -logfile "$global:LogsPath\Log.log"    }
    Pop-Location
}

Function CollectLog($RunLogs){
    Push-Location $global:LogsPath    ForEach ($RunLog in $RunLogs){		powershell.exe $RunLog        Write-Log -Message $RunLog -logfile "$global:LogsPath\Log.log"    }
    Pop-Location
}

Function CollectLogAADEXMetadata{

    $response=""
    $response=(curl -H @{"Metadata"="true"} "http://169.254.169.254/metadata/identity/info?api-version=2018-02-01" -UseBasicParsing).content
    if ($response.length){
        $response | Out-file "$global:LogsPath\AADExtention\AzureVMTenantID.txt"
        Write-Log -Message "AzureVMTenantID.txt Exported" -logfile $global:LogsPath\Log.log
    }
    
    $response=""
    $response=(curl -H @{"Metadata"="true"} "http://169.254.169.254/metadata/instance?api-version=2017-08-01" -UseBasicParsing).content
    if ($response.length){
        $response | Out-file "$global:LogsPath\AADExtention\AzuerVMInfo.txt"
        Write-Log -Message "AzuerVMInfo.txt Exported" -logfile $global:LogsPath\Log.log
    }

    $response=""
    $response=(curl -H @{"Metadata"="true"} "http://169.254.169.254/metadata/identity/oauth2/token?resource=urn:ms-drs:enterpriseregistration.windows.net&api-version=2018-02-01" -UseBasicParsing).content
    if ($response.length){
        $response | Out-file "$global:LogsPath\AADExtention\AzureVMAccessToken.txt"
        Write-Log -Message "AzureVMAccessToken.txt Exported" -logfile $global:LogsPath\Log.log
    }

}

Function StartCopyFile($Source, $Destination){
    if (Test-Path $Source){
        Copy-Item $Source -Destination $global:LogsPath\$Destination
        Write-Log -Message "$Destination has copied successfully" -logfile $global:LogsPath\Log.log
    }
}

Function CopyFiles{
    StartCopyFile "$env:windir\debug\netlogon.log" "netlogon.log"
    StartCopyFile "$env:windir\system32\drivers\etc\hosts" "hosts.txt"
    StartCopyFile "$env:windir\debug\Netsetup.log" "Netsetup.log"
    StartCopyFile "$env:windir\system32\Lsass.log" "Lsass.log"
}

Function CompressLogsFolder{    $ErrorActionPreference = "SilentlyContinue"    #$CompressedFile = "DSRegTool_Logs_" + (Get-Date -Format yyyy-MM-dd_HH-mm)    $CompressedFile = "DSRegTool_Logs_" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HH-mm')    $FolderContent = "$(Join-Path -Path $pwd.Path -ChildPath $CompressedFile).zip"    Add-Type -Assembly "System.IO.Compression.FileSystem"    [System.IO.Compression.ZipFile]::CreateFromDirectory($global:LogsPath, $FolderContent)
    Write-host "Compressed file is ready in $FolderContent" -ForegroundColor Yellow
    # Cleanup the Temporary Folder (if error retain the temp files)
    if(Test-Path -Path $pwd.Path){
		Remove-Item -Path $global:LogsPath -Force -Recurse | Out-Null
    }else{		Write-host "The Archive could not be created. Keeping Temporary Folder $global:LogsPath"		New-Item -ItemType directory -Path $pwd.Path -Force | Out-Null    }
}

Function LogmanStart($Trace,$Providers){
    logman create trace $Trace -ow -o $global:LogsPath\$Trace.etl -nb 16 16 -bs 4096 -mode circular -f bincirc -max 1024 -ets | Out-Null

    foreach ($provider in $Providers){
        $ProviderInfo = $provider.split(",")
        logman update trace $Trace -p $ProviderInfo[0] $ProviderInfo[1] $ProviderInfo[2] -ets | Out-Null
    }
    
}

Function LogmanStop($Trace){
    logman stop $Trace -ets  | Out-Null
}

Function StartLogCollection{
    $WebAuth='{2A3C6602-411E-4DC6-B138-EA19D64F5BBA},0xFFFF,0xff',`
    '{EF98103D-8D3A-4BEF-9DF2-2156563E64FA},0xFFFF,0xff',`
    '{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD},0x000003FF,0xff',`
    '{D93FE84A-795E-4608-80EC-CE29A96C8658},0x7FFFFFFF,0xff',`
    '{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5},0x7,0xff',`
    '{B1108F75-3252-4b66-9239-80FD47E06494},0x2FF,0xff',`
    '{C10B942D-AE1B-4786-BC66-052E5B4BE40E},0x3FF,0xff',`
    '{82c7d3df-434d-44fc-a7cc-453a8075144e},0x2FF,0xff',`
    '{05f02597-fe85-4e67-8542-69567ab8fd4f},0xFFFFFFFF,0xff',`
    '{3C49678C-14AE-47FD-9D3A-4FEF5D796DB9},0xFFFFFFFF,0xff',`
    '{077b8c4a-e425-578d-f1ac-6fdf1220ff68},0xFFFFFFFF,0xff',`
    '{7acf487e-104b-533e-f68a-a7e9b0431edb},0xFFFFFFFF,0xff',`
    '{5836994d-a677-53e7-1389-588ad1420cc5},0xFFFFFFFF,0xff',`
    '{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F},0xFFFFFFFF,0xff',`
    '{bfed9100-35d7-45d4-bfea-6c1d341d4c6b},0xFFFFFFFF,0xff',`
    '{9EBB3B15-B094-41B1-A3B8-0F141B06BADD},0xFFF,0xff',`
    '{6ae51639-98eb-4c04-9b88-9b313abe700f},0xFFFFFFFF,0xff',`
    '{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2},0xFFFFFFFF,0xff',`
    '{86510A0A-FDF4-44FC-B42F-50DD7D77D10D},0xFFFFFFFF,0xff',`
    '{08B15CE7-C9FF-5E64-0D16-66589573C50F},0xFFFFFF7F,0xff',`
    '{63b6c2d2-0440-44de-a674-aa51a251b123},0xFFFFFFFF,0xff',`
    '{4180c4f7-e238-5519-338f-ec214f0b49aa},0xFFFFFFFF,0xff',`
    '{EB65A492-86C0-406A-BACE-9912D595BD69},0xFFFFFFFF,0xff',`
    '{d49918cf-9489-4bf1-9d7b-014d864cf71f},0xFFFFFFFF,0xff',`
    '{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B},0xFFFF,0xff',`
    '{2A6FAF47-5449-4805-89A3-A504F3E221A6},0xFFFF,0xff',`
    '{EC3CA551-21E9-47D0-9742-1195429831BB},0xFFFFFFFF,0xff',`
    '{bb8dd8e5-3650-5ca7-4fea-46f75f152414},0xFFFFFFFF,0xff',`
    '{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290},0xFFFFFFFF,0xff',`
    '{74D91EC4-4680-40D2-A213-45E2D2B95F50},0xFFFFFFFF,0xff',`
    '{556045FD-58C5-4A97-9881-B121F68B79C5},0xFFFFFFFF,0xff',`
    '{5A9ED43F-5126-4596-9034-1DCFEF15CD11},0xFFFFFFFF,0xff',`
    '{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0},0xFFFFFFFF,0xff',`
    '{2745a526-23f5-4ef1-b1eb-db8932d43330},0xffffffffffffffff,0xff',`
    '{d48533a7-98e4-566d-4956-12474e32a680},0xffffffffffffffff,0xff',`
    '{072665fb-8953-5a85-931d-d06aeab3d109},0xffffffffffffffff,0xff',`
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF},0xffffffffffffffff,0xff',`
    '{c632d944-dddb-599f-a131-baf37bf22ef0},0xffffffffffffffff,0xff',`    '{ACC49822-F0B2-49FF-BFF2-1092384822B6},0xffffffffffffffff,0xff',`    '{5AA2DC10-E0E7-4BB2-A186-D230D79442D7},0xffffffffffffffff,0xff',`    '{7AE961F7-1262-48E2-B237-ACBA331CC970},0xffffffffffffffff,0xff',`    '{519B3601-C289-44FB-B3E4-A05841D2790D},0xffffffffffffffff,0xff',`    '{ACC49822-F0B2-49FF-BFF2-1092384822B6},0xffffffffffffffff,0xff'    $LSA='{D0B639E0-E650-4D1D-8F39-1580ADE72784},0xC43EFF,0xff',`
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB},0xffffff,0xff',`
    '{DAA76F6A-2D11-4399-A646-1D62B7380F15},0xffffff,0xff',`
    '{366B218A-A5AA-4096-8131-0BDAFCC90E93},0xfffffff,0xff',`
    '{4D9DFB91-4337-465A-A8B5-05A27D930D48},0xff,0xff',`
    '{7FDD167C-79E5-4403-8C84-B7C0BB9923A1},0xFFF,0xff',`
    '{CA030134-54CD-4130-9177-DAE76A3C5791},0xfffffff,0xff',`
    '{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e},0xffffffffffffffff,0xff',`
    '{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3},0xffffffffffffffff,0xff',`
    '{C00D6865-9D89-47F1-8ACB-7777D43AC2B9},0xffffffffffffffff,0xff',`
    '{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6},0xffffffffffffffff,0xff',`
    '{794FE30E-A052-4B53-8E29-C49EF3FC8CBE},0xffffffffffffffff,0xff',`
    '{ba634d53-0db8-55c4-d406-5c57a9dd0264},0xffffffffffffffff,0xff'    $Ntlm_CredSSP='{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90},0x5ffDf,0xff',`
    '{AC43300D-5FCC-4800-8E99-1BD3F85F0320},0xffffffffffffffff,0xff',`
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9},0xffffffff,0xff',`
    '{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E},0xffffffffffffffff,0xff',`
    '{AC69AE5B-5B21-405F-8266-4424944A43E9},0xffffffff,0xff'    $Kerberos='{97A38277-13C0-4394-A0B2-2A70B465D64F},0xff,0xff',`
    '{FACB33C4-4513-4C38-AD1E-57C1F6828FC0},0xffffffff,0xff',`
    '{8a4fc74e-b158-4fc1-a266-f7670c6aa75d},0xffffffffffffffff,0xff',`
    '{60A7AB7A-BC57-43E9-B78A-A1D516577AE3},0xffffff,0xff',`
    '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1},0xffffffffffffffff,0xff',`
    '{6B510852-3583-4e2d-AFFE-A67F9F223438},0x7ffffff,0xff'    #Create DSRegToolLogs folder.
    Write-Log -Message "Log collection has started"
    Write-Host "Creating DSRegToolLogs folder under $pwd" -ForegroundColor Yellow
    if (!(Test-Path $global:LogsPath)){
        New-Item -itemType Directory -Path $global:LogsPath -Force | Out-Null
        Write-Log -Message "Log collection has started" -logfile "$global:LogsPath\Log.log"
        $msg="Log collection started on device name: " + (Get-Childitem env:computername).value
        Write-Log -Message $msg -logfile "$global:LogsPath\Log.log"
        $msg="Log collection started by user name: " + (whoami) +", UPN: "+$global:UserUPN
        Write-Log -Message $msg -logfile "$global:LogsPath\Log.log"
        Write-Log -Message "DSRegToolLogs folder created under $pwd" -logfile "$global:LogsPath\Log.log"
    }else{
        Remove-Item -Path $global:LogsPath -Force -Recurse | Out-Null
        New-Item -itemType Directory -Path $global:LogsPath -Force | Out-Null
        Write-Log -Message "Clear old DSRegToolLogs folder" -logfile "$global:LogsPath\Log.log"
        $msg="Log collection started on device name: " + (Get-Childitem env:computername).value
        Write-Log -Message $msg -logfile "$global:LogsPath\Log.log"
        $msg="Log collection started by user name: " + (whoami) +", UPN: "+$global:UserUPN
        Write-Log -Message $msg -logfile "$global:LogsPath\Log.log"
        Write-Log -Message "DSRegToolLogs folder created under $pwd" -logfile "$global:LogsPath\Log.log"
    }

    #Create PreTrace in DSRegToolLogs folder.
    Write-Host "Checking PreTrace folder under $pwd\DSRegToolLogs" -ForegroundColor Yellow
    Write-Log -Message "Checking PreTrace folder under $pwd\DSRegToolLogs" -logfile "$global:LogsPath\Log.log"
    $global:PreTrace=$pwd.Path+"\DSRegToolLogs\PreTrace"
    if (!(Test-Path $global:PreTrace)){
        New-Item -itemType Directory -Path $global:PreTrace -Force | Out-Null
        Write-Log -Message "PreTrace folder created under $global:LogsPath" -logfile "$global:LogsPath\Log.log"
    }

    #PreTrace
    Write-Host "Collecting PreTrace logs..." -ForegroundColor Yellow
    Write-Log -Message "Collecting PreTrace logs..." -logfile "$global:LogsPath\Log.log"
    ExportEventViewerLogs $global:PreTraceEvents $global:PreTrace
    dsregcmd /status | Out-file "$global:PreTrace\dsregcmd-status.txt"    Write-Log -Message "dsregcmd-status.txt created in PreTrace folder" -logfile "$global:LogsPath\Log.log"    RunPScript -PSScript "dsregcmd /status /debug" | Out-file "$global:PreTrace\dsregcmd-debug.txt"    Write-Log -Message "dsregcmd-debug.txt created in PreTrace folder" -logfile "$global:LogsPath\Log.log"    #Press ENTER to start log collection:    Write-Host ''    Write-Host "Please press ENTER to start log collection..." -ForegroundColor Green -NoNewline    Write-Log -Message "Please press ENTER to start log collection..." -logfile "$global:LogsPath\Log.log"    Read-Host    Write-Host "Starting log collection..." -ForegroundColor Yellow    Write-Log -Message "Starting log collection..." -logfile "$global:LogsPath\Log.log"    #Enable debug and network logs:    Write-Host "Enabling debug logs..." -ForegroundColor Yellow    Write-Log -Message "Enabling debug logs..." -logfile "$global:LogsPath\Log.log"    EnableDebugEvents $global:DebugLogs    Write-Host "Starting network traces..." -ForegroundColor Yellow    Write-Log -Message "Starting network traces..." -logfile "$global:LogsPath\Log.log"    LogmanStart "WebAuth" $WebAuth    Write-Log -Message "WebAuth log collection started..." -logfile "$global:LogsPath\Log.log"    LogmanStart "LSA" $LSA    Write-Log -Message "LSA log collection started..." -logfile "$global:LogsPath\Log.log"    LogmanStart "Ntlm_CredSSP" $Ntlm_CredSSP    Write-Log -Message "Ntlm_CredSSP log collection started..." -logfile "$global:LogsPath\Log.log"    LogmanStart "Kerberos" $Kerberos    Write-Log -Message "Kerberos log collection started..." -logfile "$global:LogsPath\Log.log"    $Reg=Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions -ErrorAction SilentlyContinue
    if ($Reg.ProductType -eq "WinNT"){
        netsh trace start InternetClient persistent=yes traceFile=.\DSRegToolLogs\Netmon.etl capture=yes maxsize=1024| Out-Null
        Write-Log -Message "Network trace started..." -logfile "$global:LogsPath\Log.log"
    }else{
        netsh trace start persistent=yes traceFile=.\DSRegToolLogs\Netmon.etl capture=yes maxsize=1024| Out-Null
        Write-Log -Message "Network trace started..." -logfile "$global:LogsPath\Log.log"
    }
    Write-Host ''    Write-Host ''    Write-Host "Log collection has started, please start repro the issue..." -ForegroundColor Yellow    Write-Log -Message "Log collection has started, please start repro the issue..." -logfile "$global:LogsPath\Log.log"    Write-Host ''}Function StopLogCollection{    Write-Host "When repro finished, please press ENTER to stop log collection..." -ForegroundColor Green -NoNewline    Write-Log -Message "When repro finished, please press ENTER to stop log collection..." -logfile "$global:LogsPath\Log.log"    Read-Host     #Disable debug and analytic logs:    DisableDebugEvents $global:DebugLogs    #Collect logs    Write-Host "Log collection has been stopped, please wait until we gather all files..." -ForegroundColor Yellow    Write-Log -Message "Log collection has been stopped, please wait until we gather all files..." -logfile "$global:LogsPath\Log.log"    Write-Host "Copying files..." -ForegroundColor Yellow    write-log -Message "Copying files..." -logfile "$global:LogsPath\Log.log"    CopyFiles    Write-Host "Exporting registry keys..." -ForegroundColor Yellow    write-log -Message "Exporting registry keys..." -logfile "$global:LogsPath\Log.log"    CollectLog $global:RegKeys    Write-Host "Exporting event viewer logs..." -ForegroundColor Yellow    CollectAdditionalLogs    write-log -Message "Exporting event viewer logs..." -logfile "$global:LogsPath\Log.log"    ExportEventViewerLogs $global:Events $global:LogsPath    RunPScript -PSScript "dsregcmd /status /debug" | Out-file "$global:LogsPath\dsregcmd-debug.txt"    Write-Log -Message "dsregcmd-debug.txt exported" -logfile "$global:LogsPath\Log.log"    getSCP    getwinHTTPinInet    CollectLogAADExt $global:AADExt    CollectLogAADEXMetadata    Write-Host "Stopping network traces, this may take few minutes..." -ForegroundColor Yellow    Write-Log -Message "Stopping network traces, this may take few minutes..." -logfile "$global:LogsPath\Log.log"    LogmanStop "WebAuth"    Write-Log -Message "WebAuth log collection stopped..." -logfile "$global:LogsPath\Log.log"    LogmanStop "LSA"    Write-Log -Message "LSA log collection stopped..." -logfile "$global:LogsPath\Log.log"    LogmanStop "Ntlm_CredSSP"    Write-Log -Message "Ntlm_CredSSP log collection stopped..." -logfile "$global:LogsPath\Log.log"    LogmanStop "Kerberos"    Write-Log -Message "Kerberos log collection stopped..." -logfile "$global:LogsPath\Log.log"    netsh trace stop | Out-Null    Test-DevRegConnectivity $false | Out-file "$global:LogsPath\TestDeviceRegConnectivity-system.txt"    Write-Log -Message "TestDeviceRegConnectivity-system.txt exported" -logfile "$global:LogsPath\Log.log"    Test-DevRegConnectivity-User $false | Out-file "$global:LogsPath\TestDeviceRegConnectivity-user.txt"    Write-Log -Message "TestDeviceRegConnectivity-user.txt exported" -logfile "$global:LogsPath\Log.log"    Write-Log -Message "Log collection completed successfully"    Write-Host "Compressing collected logs..." -ForegroundColor Yellow    if (Test-Path "$pwd\DSRegTool.log"){
        Copy-Item "$pwd\DSRegTool.log" -Destination "$global:LogsPath\DSRegTool.log" | Out-Null
        Write-Log -Message "DSRegTool.log has copied" -logfile "$global:LogsPath\Log.log"
    }
    Write-Log -Message "Log collection completed successfully, compressing collected logs..." -logfile "$global:LogsPath\Log.log"    CompressLogsFolder
    Write-Host ''
    Write-Host ''
    Write-Host "Log collection completed successfully" -ForegroundColor Green -NoNewline
    Write-Host ''
    Write-Host ''
}

Function CollectAdditionalLogs{
    $ErrorActionPreference= 'silentlycontinue'
    $DeviceInfo=""
    $OSVer = (([environment]::OSVersion).Version).ToString()
    $DeviceInfo+= "OS version         : " + $OSVer + "`n"
    $DeviceInfo+= "Device Name        : " + (Get-Childitem env:computername).value + "`n"
    $DeviceGUID=(new-object guid(,(([ADSI](([adsisearcher]"(&(objectCategory=computer)(objectClass=computer)(cn=$env:COMPUTERNAME))").findall().path)).ObjectGuid)[0])).Guid 
    $DeviceInfo+= "Object GUID        : $DeviceGUID" + "`n"
    $DeviceDN = ((([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().path).tostring() -split "LDAP://")[1].trim()
    $DeviceInfo+= "Distinguished Name : " + $DeviceDN + "`n`n"
    $userCerts=([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().Properties.usercertificate
    $userCertCount=$userCerts.count
    $userCertResult= "UserCertificate count: $userCertCount `n"
    foreach ($userCert in $userCerts){
        $userCert=(new-object X509Certificate(,$userCert))
        $userCertResult+="Handle  : " + $userCert.Handle + "`n"
        $userCertResult+="Issuer  : " + $userCert.Issuer + "`n"
        $userCertResult+="Subject : " + $userCert.Subject + "`n"
        $userCertResult+="`n"
    }
    $DeviceInfo+=$userCertResult
    $DeviceInfo | Out-File "$global:LogsPath\DeviceInfo.txt"
    
    (schtasks.exe /query /v 2>&1) | Out-File "$global:LogsPath\Task-Scheduler.txt"
    Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion' | Out-File "$global:LogsPath\Build.txt"
}

Function LogsCollection{
    Write-Host ''
    Write-Host "Testing if script running with elevated privileges..." -ForegroundColor Yellow 
    Write-Log -Message "Testing if script running with elevated privileges..."
    if (PSasAdmin){
        # PS running as admin.
        Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green
        Write-Log -Message "PowerShell is running with elevated privileges"
        Write-Host ''
    }else{
        Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red
        Write-Log -Message "PowerShell is NOT running with elevated privileges" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run log collection option with elevated privileges, or otherwise, follow the following action plan to collect logs using Feedback Hub:`n"  -ForegroundColor Yellow
        Write-Host " - Open Feedback Hub by pressing (Windows key + F)"
        Write-Host " - Make sure 'Advanced diagnostics' tab is visible. Otherwise click on settings and select 'Show Advanced Diagnostics page' checkbox"
        Write-Host " - Click on Advanced Diagnostics tab"
        Write-Host " - Choose 'Default diagnostics' option"
        Write-Host " - From 'Select which diagnostic to collect' dropdown list, select 'Security and Privacy' and 'Work or School Account'"
        Write-Host " - Click on 'Start recording' when you are ready"
        Write-Host " - Repro the issue"
        Write-Host " - Click on 'Stop recording'"
        Write-Host " - Click on 'File location' to open 'Security and privacy-Work or School-Repro' folder"
        Write-Host " - Open latest created Repro folder"
        Write-Host " - Share 'diagnostics.zip' compressed file with Microsoft support engineer"
        Write-Log -Message "Recommended action: Run log collection option with elevated privileges, or otherwise follow the following action plan to collect logs using Feedback Hub:`n                                 - Open Feedback Hub by pressing (Windows key + F)`n                                 - Make sure 'Advanced diagnostics' tab is visible. Otherwise click on settings and select 'Show Advanced Diagnostics age' checkbox`n                                 - Click on Advanced Diagnostics tab`n                                 - Choose 'Default diagnostics' option`n                                 - From 'Select which diagnostic to collect' ropdown list, select 'Security and Privacy' and 'Work or School Account'`n                                 - Click on 'Start recording' when you are ready`n                                 - Repro the issue`n                                 - Click on 'Stop recording'`n                                 - Click on 'File location' to open 'Security and privacy-Work or School-Repro' folder`n                                 - Open latest created Repro folder`n                                 - Share 'diagnostics.zip' compressed file with Microsoft support engineer"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }

    $global:LogsPath=$pwd.Path+"\DSRegToolLogs"
    $global:PreTraceEvents = "Microsoft-Windows-AAD/Operational","Microsoft-Windows-User Device Registration/Admin","Microsoft-Windows-CAPI2/Operational","Microsoft-Windows-HelloForBusiness/Operational","Microsoft-Windows-LiveId/Operational","Microsoft-Windows-User Control Panel/Operational","Microsoft-Windows-WebAuth/Operational","Microsoft-Windows-WebAuthN/Operational","Microsoft-Windows-Biometrics/Operational","Microsoft-Windows-IdCtrls/Operational","Microsoft-Windows-Crypto-DPAPI/Operational"
    $global:DebugLogs="Microsoft-Windows-AAD/Analytic","Microsoft-Windows-User Device Registration/Debug", "Microsoft-Windows-AADRT/Admin"
    $global:Events = $global:PreTraceEvents + "Microsoft-Windows-AAD/Analytic","Microsoft-Windows-User Device Registration/Debug","System","Application","Microsoft-Windows-Shell-Core/Operational","Microsoft-Windows-Kerberos/Operational","Microsoft-Windows-CertPoleEng/Operational","Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController","Microsoft-Windows-Authentication/ProtectedUser-Client","Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController","Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-GroupPolicy/Operational","Microsoft-Windows-LAPS/Operational"

    $global:RegKeys = 'ipconfig /all > ipconfig-all.txt',`
    'dsregcmd /status > dsregcmd-status.txt',`
    'dsregcmd /status > dsregcmd.txt',`
    '[environment]::OSVersion | fl * > Winver.txt',`
    'netstat -nao > netstat-nao.txt',`
    'route print > route-print.txt',`
    'net start > services-running.txt',`
    'tasklist > tasklist.txt',`
    'wmic qfe list full /format:htable > Patches.htm',`
    'GPResult /f /h GPResult.html',`
    'regedit /e CloudDomainJoin.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin',`
    'regedit /e Lsa.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa',`
    'regedit /e Netlogon.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon',`
    'regedit /e Schannel.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',`
    'regedit /e StrongCrypto.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',`
    'regedit /e Winlogon.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',`
    'regedit /e CDJ.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ',`
    "regedit /e AADLoginForWindowsExtension.txt 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Azure\CurrentVersion\AADLoginForWindowsExtension'",`

    'regedit /e Winlogon-current-control-set.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon',`
    'regedit /e IdentityStore.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore',`
    'regedit /e WorkplaceJoin-windows.txt HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin',`
    'regedit /e WorkplaceJoin-control.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WorkplaceJoin',`
    'regedit /e WPJ-info.txt HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD',`

    'regedit /e LAPS_SCP.txt HKEY_LOCAL_MACHINE\Software\Microsoft\Policies\LAPS',`
    'regedit /e LAPS_GPO.txt HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS',`
    'regedit /e LAPS_LocalConfig.txt HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\LAPS\Config',`
    'regedit /e LAPS_Legacy.txt HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd'

    $global:AADExt='set > set.txt',`
    'sc query  > services-config.txt',`    'md AADExtention',`    'curl https://login.microsoftonline.com/ -D - > .\AADExtention\login.microsoftonline.com.txt 2>&0',`    'curl https://enterpriseregistration.windows.net/ -D - > .\AADExtention\enterpriseregistration.windows.net.txt 2>&0',`    'curl https://device.login.microsoftonline.com/ -D - > .\AADExtention\device.login.microsoftonline.com.txt 2>&0',`    'curl https://pas.windows.net/ -D - > .\AADExtention\pas.windows.net.txt 2>&0',`    'xcopy C:\WindowsAzure\Logs\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows .\AADExtention\Microsoft.Azure.ActiveDirectory.AADLoginForWindows /E /H /C /I >null 2>&1'
    If ((((New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration "Microsoft-Windows-AAD/Analytic").IsEnabled) -and ((New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration "Microsoft-Windows-User Device Registration/Debug").IsEnabled))){        write-Host "Debug logs are enabled, it seems you started log collection" -ForegroundColor Yellow        Write-Log -Message "Debug logs are enabled, it seems you started log collection" -logfile "$global:LogsPath\Log.log"        write-Host "Do you want to continue with current log collection? [Y/N]" -ForegroundColor Yellow        Write-Log -Message "Do you want to continue with current log collection? [Y/N]" -logfile "$global:LogsPath\Log.log"        $input=Read-Host "Enter 'Y' to continue, or 'N' to start a new log collection"        While(($input -ne 'y') -AND ($input -ne 'n')){
            $input = Read-Host -Prompt "Invalid input. Please make a correct selection from the above options, and press Enter" 
        }        if($input -eq 'y'){            Write-Log -Message "Continue option has selected" -logfile "$global:LogsPath\Log.log"            #Test if DSRegToolLog folder exist            if(Test-Path $global:LogsPath){                #Stop log collection, when repro finished, please press ENTER.                StopLogCollection            }else{                Write-Host ''                Write-Host "Please locate DSRegToolLog folder/path where you start the tool previously, and start the tool again" -ForegroundColor Red                write-log -Message "Please locate DSRegToolLog folder/path where you start the tool previously, and start the tool again" -Level ERROR            }        }elseif($input -eq 'n'){            Write-Log -Message "Start new collection option has selected" -logfile "$global:LogsPath\Log.log"            #Start log collection from bigning            StartLogCollection            StopLogCollection        }    }else{        #Start log collection from bigning        StartLogCollection        StopLogCollection    }
}
#Eng of Log Collection functions

Function CheckInternet{
$statuscode = (Invoke-WebRequest -Uri https://adminwebservice.microsoftonline.com/ProvisioningService.svc -UseBasicParsing).statuscode
    if ($statuscode -ne 200){
        Write-Host ''
        Write-Host ''
        Write-Host "Operation aborted. Unable to connect to Microsoft Entra ID." -ForegroundColor red
        Write-Log -Message "Operation aborted. Unable to connect to Microsoft Entra ID."
        Write-Host ''
        Write-Host "Recommended action: Please check your internet connection." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Please check your internet connection." -Level ERROR
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }
}

Function CheckMSOnline{
    Write-Host ''
    Write-Host "Checking if there is an active session to MSOnline..." -ForegroundColor Yellow
    Write-Log -Message "Checking if there is an active session to MSOnline..."
    Get-MsolDomain | Out-Null -ErrorAction SilentlyContinue
    if($?)
    {
        Write-Host "There is an active session to MSOnline" -ForegroundColor Green
        Write-Log -Message "There is an active session to MSOnline"
    }
    else
    {
        Write-Host "There no active session to MSOnline" -ForegroundColor Yellow
        Write-Log -Message "There is no active session to MSOnline"

        Write-Host ''
        Write-Host "Checking MSOnline Module..." -ForegroundColor Yellow
        Write-Log -Message "Checking MSOnline Module..."
        if (Get-Module -ListAvailable -Name MSOnline) {
            Import-Module MSOnline
            Write-Host "MSOnline Module has imported" -ForegroundColor Green
            Write-Log -Message "MSOnline Module has imported"
            Write-Host ''
            Write-Host "Checking MSOnline version..." -ForegroundColor Yellow
            Write-Log -Message "Checking MSOnline version..."
            $MVersion = Get-Module msonline | Select-Object version
            if (($MVersion.Version.Major -eq 1) -and ($MVersion.Version.Minor -eq 1) -and ($MVersion.Version.Build -ge 183)){
                Write-Host "You have a supported version" -ForegroundColor Green
                Write-Log -Message "You have a supported version"
            }else{
                Write-Host "You have an old version" -ForegroundColor Red
                Write-Log -Message "You have an old version"
                Write-Host ''
                Write-Host "Updating MSOnline version..." -ForegroundColor Yellow
                Write-Log -Message "Updating MSOnline version..."
                Update-Module msonline -force
                Remove-Module msonline
                Import-Module msonline
                $MVersion = Get-Module msonline | Select-Object version
                if (($MVersion.Version.Major -eq 1) -and ($MVersion.Version.Minor -eq 1) -and ($MVersion.Version.Build -ge 183)){
                    Write-Host "MSOnline Module has been updated, please reopen PowerShell window" -ForegroundColor Green
                    Write-Log -Message "MSOnline Module has been updated, please reopen PowerShell window"
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                    Write-Host ''
                    exit
                }else{
                    Write-Host "Operation aborted. MSOnline module has not updated, please make sure you are running PowerShell as admin" -ForegroundColor red
                    Write-Log -Message "Operation aborted. MSOnline module has not updated, please make sure you are running PowerShell as admin"
                    exit
                }
            }
            Write-Host ''
            Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
            Write-Log -Message "Connecting to MSOnline..."
            if ($SavedCreds){
                Connect-MsolService -Credential $UserCreds -ErrorAction SilentlyContinue
            }else{
                Connect-MsolService -ErrorAction SilentlyContinue
            }
            if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
                Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
                Write-Log -Message "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions"
                exit
            }
            Write-Host "Connected to MSOnline successfully." -ForegroundColor Green
            Write-Log -Message "Connected to MSOnline successfully."
        } else {
            Write-Host "MSOnline Module is not installed" -ForegroundColor Red
            Write-Log -Message "MSOnline Module is not installed"
            Write-Host "Installing MSOnline Module....." -ForegroundColor Yellow
            Write-Log -Message "Installing MSOnline Module....."
            CheckInternet
            Install-Module MSOnline -force
            if (Get-Module -ListAvailable -Name MSOnline) {                                
            Write-Host "MSOnline Module has installed" -ForegroundColor Green
            Write-Log -Message "MSOnline Module has installed"
            Import-Module MSOnline
            Write-Host "MSOnline Module has imported" -ForegroundColor Green
            Write-Log -Message "MSOnline Module has imported"
            Write-Host ''
            Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
            Write-Log -Message "Connecting to MSOnline..." 
            Connect-MsolService -ErrorAction SilentlyContinue
            if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
                Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
                Write-Log -Message "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions"
                exit
            }
            Write-Host "Connected to MSOnline successfully." -ForegroundColor Green
            Write-Log -Message "Connected to MSOnline successfully."
            Write-Host ''
            } else {
            Write-Host ''
            Write-Host ''
            Write-Host "Operation aborted. MsOnline was not installed" -ForegroundColor red
            Write-Log -Message "Operation aborted. MsOnline was not installed"
            exit
            }
        }
    }
}

Function RunPScript([String] $PSScript){
    $GUID=[guid]::NewGuid().Guid

    $Job = Register-ScheduledJob -Name $GUID -ScheduledJobOption (New-ScheduledJobOption -RunElevated) -ScriptBlock ([ScriptBlock]::Create($PSScript)) -ArgumentList ($PSScript) -ErrorAction Stop

    $Task = Register-ScheduledTask -TaskName $GUID -Action (New-ScheduledTaskAction -Execute $Job.PSExecutionPath -Argument $Job.PSExecutionArgs) -Principal (New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest) -ErrorAction Stop

    $Task | Start-ScheduledTask -AsJob -ErrorAction Stop | Wait-Job | Remove-Job -Force -Confirm:$False

    While (($Task | Get-ScheduledTaskInfo).LastTaskResult -eq 267009) {Start-Sleep -Milliseconds 150}

    $Job1 = Get-Job -Name $GUID -ErrorAction SilentlyContinue | Wait-Job
    $Job1 | Receive-Job -Wait -AutoRemoveJob 

    Unregister-ScheduledJob -Id $Job.Id -Force -Confirm:$False

    Unregister-ScheduledTask -TaskName $GUID -Confirm:$false
}

Function CheckCert ([String] $DeviceID, [String] $DeviceThumbprint){

    #Search for the certificate:
    if ($localCert = dir Cert:\LocalMachine\My\ | where { $_.Issuer -match "CN=MS-Organization-Access" -and $_.Subject -match "CN="+$DeviceID}){
        #The certificate exists
        Write-Host "Certificate does exist." -ForegroundColor Green
        #Cheching the certificate configuration
        $CertSubject = $localCert.subject
        $CertDNSNameList = $localCert.DnsNameList
        $CertThumbprint = $localCert.Thumbprint
        $NotBefore = $localCert.NotBefore
        $NotAfter = $localCert.NotAfter
        $IssuerName = $localCert.IssuerName
        $Issuer = $localCert.Issuer
        $subbectName = $localCert.SubjectName
        $Algorithm = $localCert.SignatureAlgorithm
        $PublicKey = $localCert.PublicKey
        $HasPrivateKey = $localCert.HasPrivateKey

        # Check Cert Expiration
        if (($NotAfter.toString("yyyy-M-dd")) -gt (Get-Date -format yyyy-M-dd)){
            Write-Host "Certificate is not expired." -ForegroundColor Green
        }else{
            Write-Host "The certificate has expired." -ForegroundColor Red
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            exit
        }

        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode
        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            Write-Host "The certificate subject is not correct." -ForegroundColor Red
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate subject is correct." -ForegroundColor Green
        }

        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            Write-Host "Certificate Issuer is not configured correctly." -ForegroundColor Red
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate issuer is correct." -ForegroundColor Green
        }

        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            Write-Host "Certificate Algorithm is not configured correctly." -ForegroundColor Red
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate Algorithm is correct." -ForegroundColor Green
        }

        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            Write-Host "Certificate Algorithm Value is not configured correctly." -ForegroundColor Red
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate Algorithm Value is correct." -ForegroundColor Green
        }
        
        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            Write-Host "Certificate PrivateKey does not exist." -ForegroundColor Red
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate PrivateKey is correct." -ForegroundColor Green
        }

    }else{
        #Certificate does not exist.
        Write-Host "Device certificate does not exist." -ForegroundColor Red
        Write-Host ''
        Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again." -ForegroundColor Yellow
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Host ''
        Write-Host ''
        exit
    }
}#End of function

Function CheckUserCert ([String] $DeviceID, [String] $DeviceThumbprint){
    #Search for the certificate:
    if ($localCert = dir Cert:\CurrentUser\My\ | where { $_.Issuer -match "CN=MS-Organization-Access" -and $_.Subject -match "CN="+$DeviceID}){
    #The certificate exists
    Write-Host "Certificate does exist" -ForegroundColor Green
    Write-Log -Message "Certificate does exist"
    #Cheching the certificate configuration
    $CertSubject = $localCert.subject
    $CertDNSNameList = $localCert.DnsNameList
    $CertThumbprint = $localCert.Thumbprint
    $NotBefore = $localCert.NotBefore
    $NotAfter = $localCert.NotAfter
    $IssuerName = $localCert.IssuerName
    $Issuer = $localCert.Issuer
    $subbectName = $localCert.SubjectName
    $Algorithm = $localCert.SignatureAlgorithm
    $PublicKey = $localCert.PublicKey
    $HasPrivateKey = $localCert.HasPrivateKey
    # Check Cert Expiration
    if (($NotAfter.toString("yyyy-M-dd")) -gt (Get-Date -format yyyy-M-dd)){
        Write-Host "Certificate is not expired" -ForegroundColor Green
        Write-Log -Message "Certificate is not expired"
    }else{
        Write-Host "The certificate has expired" -ForegroundColor Red
        Write-Log -Message "The certificate has expired" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }
        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode

        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            Write-Host "The certificate subject is not correct" -ForegroundColor Red
            Write-Log -Message "The certificate subject is not correct" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit

        }else{
            Write-Host "Certificate subject is correct" -ForegroundColor Green
            Write-Log -Message "Certificate subject is correct"
        }

        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            Write-Host "Certificate Issuer is not configured correctly" -ForegroundColor Red
            Write-Log -Message "Certificate Issuer is not configured correctly" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit

        }else{
            Write-Host "Certificate issuer is correct" -ForegroundColor Green
            Write-Log -Message "Certificate issuer is correct"
        }

        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            Write-Host "Certificate Algorithm is not configured correctly" -ForegroundColor Red
            Write-Log -Message "Certificate Algorithm is not configured correctly" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate Algorithm is correct" -ForegroundColor Green
            Write-Log -Message "Certificate Algorithm is correct"
        }

        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            Write-Host "Certificate Algorithm Value is not configured correctly" -ForegroundColor Red
            Write-Log -Message "Certificate Algorithm Value is not configured correctly" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit

        }else{
            Write-Host "Certificate Algorithm Value is correct" -ForegroundColor Green
            Write-Log -Message "Certificate Algorithm Value is correct"
        }
        
        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            Write-Host "Certificate PrivateKey does not exist" -ForegroundColor Red
            Write-Log -Message "Certificate PrivateKey does not exist" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Certificate PrivateKey is correct" -ForegroundColor Green
            Write-Log -Message "Certificate PrivateKey is correct"
        }

    }else{
    #Certificate does not exist.
    Write-Host "Device certificate does not exist" -ForegroundColor Red
    Write-Log -Message "Device certificate does not exist"
    Write-Host ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
    Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''
    exit
    }
    

}#End of function

function Connect-AzureDevicelogin {
    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 1
        #$Timeout = 300
    )
try {
    $DeviceCodeRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
        Body   = @{
            resource  = $Resource
            client_id = $ClientId
            redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
    }
    $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
 
    # Copy device code to clipboard
    $DeviceCode = ($DeviceCodeRequest.message -split "code " | Select-Object -Last 1) -split " to authenticate."
    Set-Clipboard -Value $DeviceCode

    Write-Host ''
    Write-Host "Device code " -ForegroundColor Yellow -NoNewline
    Write-Host $DeviceCode -ForegroundColor Green -NoNewline
    Write-Host "has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the sign in, and close the window to proceed." -ForegroundColor Yellow
    Write-Host "Note: If 'Microsoft Graph Authentication' window didn't open,"($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1) -ForegroundColor gray
    $msg= "Device code $DeviceCode has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the signin, and close the window to proceed.`n                                 Note: If 'Microsoft Graph Authentication' window didn't open,"+($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1)
    Write-Log -Message $msg

    # Open Authentication form window
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
    $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 440; Height = 600; Url = "https://www.microsoft.com/devicelogin" }
    $web.Add_DocumentCompleted($DocComp)
    $web.DocumentText
    $form.Controls.Add($web)
    $form.Add_Shown({ $form.Activate() })
    $web.ScriptErrorsSuppressed = $true
    $form.AutoScaleMode = 'Dpi'
    $form.text = "Microsoft Graph Authentication"
    $form.ShowIcon = $False
    $form.AutoSizeMode = 'GrowAndShrink'
    $Form.StartPosition = 'CenterScreen'
    $form.ShowDialog() | Out-Null
        
    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        Body   = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            code       = $DeviceCodeRequest.device_code
            client_id  = $ClientId
        }
    }
    $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
        if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
            throw 'Login timed out, please try again.'
        }
        $TokenRequest = try {
            Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
        }
        catch {
            $Message = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($Message.error -ne "authorization_pending") {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
    Write-Output $TokenRequest.access_token
}
finally {
    try {
        Remove-Item -Path $TempPage.FullName -Force -ErrorAction Stop
        $TimeoutTimer.Stop()
    }
    catch {
        #Ignore errors here
    }
}
}

Function ConnecttoAzureAD{
    Write-Host ''
    Write-Host "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    Write-Log -Message "Checking if there is a valid Access Token..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if($GraphResult.value.Count)
    {
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg

    }else{
        Write-Host "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
        Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token"
        $global:accesstoken = Connect-AzureDevicelogin
        ''
        if ($global:accesstoken.Length -ge 1){
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg
        }
    }

}
Function CheckDeviceHealth($DID, $skipPendingCheck){
    ConnecttoAzureAD
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }

    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$DID'"
    try{
        $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
        $AADDevice=$GraphResult.Content | ConvertFrom-Json
        if($AADDevice.value.Count -ge 1){
            #Device returned
            $deviceExists=$true
            $deviceEnabled = $AADDevice.value.accountEnabled
            $LastLogonTimestamp=$AADDevice.value.approximateLastSignInDateTime

            $Cert=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($AADDevice.value.alternativeSecurityIds.key))
            $AltSec = $Cert -replace $cert[1]

            if (-not ($AltSec.StartsWith("X509:"))){
                $devicePending=$true
            }else{
                $devicePending=$false
            }

        }else{
            #Device does not exist
            $deviceExists=$false
        }
    }catch{
        Write-Host ''
        Write-Host "Operation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Host ''
        Write-Host ''
        exit
    }

    Write-Host ''
    Write-Host "Testing device status on Microsoft Entra ID..." -ForegroundColor Yellow
    Write-Log -Message "Testing device status on Microsoft Entra ID..."

    #Check if the device exist:
    ''
    Write-Host "Testing if device exists on Microsoft Entra ID..." -ForegroundColor Yellow
    Write-Log -Message "Testing if device exists on Microsoft Entra ID..."
    if ($deviceExists){
        #The device existing in AAD:
        Write-Host "Test passed: the device object exists on Microsoft Entra ID" -ForegroundColor Green
        Write-Log -Message "Test passed: the device object exists on Microsoft Entra ID"
    }else{
        #Device does not exist:
        ###Rejoin device to AAD
        Write-Host "Test failed: the device does not exist in your Microsoft Entra tenant" -ForegroundColor Red
        Write-Log -Message "Test failed: the device does not exist in your Microsoft Entra tenant" -Level ERROR
        ''
        Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again. If you have a Managed domain, make sure the device is in the sync scope."
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        ''
        ''
        exit
    }

    #Check if the device is enabled:
    ''
    Write-Host "Testing if device is enabled on Microsoft Entra ID..." -ForegroundColor Yellow
    Write-Log -Message "Testing if device is enabled on Microsoft Entra ID..."
    if ($deviceEnabled){
        Write-Host "Test passed: the device is enabled on Microsoft Entra tenant" -ForegroundColor Green
        Write-Log -Message "Test passed: the device is enabled on Microsoft Entra tenant"
    }else{
        Write-Host "Test failed: the device is not enabled on Microsoft Entra tenant" -ForegroundColor Red
        Write-Log -Message "Test failed: the device is not enabled on Microsoft Entra tenant" -Level ERROR
        ''
        Write-Host "Recommended action: Enable the device on Microsoft Entra ID. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Enable the device on Microsoft Entra ID. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device."
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        ''
        ''
        exit
    }

    if(!($skipPendingCheck)){
        #Check if the device is registered (not Pending):
        Write-Host ''
        Write-Host "Testing device PENDING state..." -ForegroundColor Yellow
        Write-Log -Message "Testing device PENDING state..."
        if ($devicePending){
            Write-Host "Test failed: the device in 'Pending' state on Microsoft Entra ID." -ForegroundColor Red
            Write-Log -Message "Test failed: the device in 'Pending' state on Microsoft Entra ID."
            Write-Host ''
            Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
            Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin." -ForegroundColor Yellow
            Write-Host "                     - Run 'dsregcmd /join' command as admin to performMicrosoft Entra hybrid joined procedure and re-run the script." -ForegroundColor Yellow
            Write-Host ''
            Write-Host "Note: if the issue still persists, check the possible causes on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
            Write-Log -Message "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:`n                                 - Clear the device state by running the command 'dsregcmd /leave' as admin.`n                                 - Run 'dsregcmd /join' command as admin to performMicrosoft Entra hybrid joined procedure and re-run the script.`n    `n                                 Note: if the issue still persists, check the possible causes on the article: http://www.microsoft.com/aadjerrors"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
                Write-Host "Test passed: the device is not in PENDING state" -ForegroundColor Green
                Write-Log -Message "Test passed: the device is not in PENDING state"
        }
    }

    Write-Host ''
    Write-Host "Checking if device is stale..." -ForegroundColor Yellow
    Write-Log -Message "Checking if device is stale..."
    $CurrentDate = Get-Date 
    $Diff = New-TimeSpan -Start $LastLogonTimestamp -End $CurrentDate
    $diffDays=$Diff.Days
    if(($diffDays -ge 21) -or ($diffDays.length -eq 0)){
        Write-Host "Device could be stale" -ForegroundColor Yellow
        Write-Log -Message "Device could be stale" -Level WARN
    }else{
    Write-Host "Device is not stale" -ForegroundColor Green
        Write-Log -Message "Device is not stale"
    }
    if($diffDays.length -eq 0) {
        Write-Host "There is no sign in yet on this device" -ForegroundColor Yellow
        Write-Log -Message "There is no sign in yet on this device" -Level WARN
    }else{
        Write-Host "Last logon timestamp: $LastLogonTimestamp UTC, $diffDays days ago" -ForegroundColor Green
        $msg= "Last logon timestamp: $LastLogonTimestamp UTC, $diffDays day(s) ago"
        Write-Log -Message $msg
    }
}

Function NewFun{
    #The device is Microsoft Entra hybrid joined
    $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host $hostname "device is joined to Microsoft Entra tenant:" $TenantName -ForegroundColor Green
    Write-Log -Message "$hostname device is joined to Microsoft Entra tenant: $TenantName"
    Write-Host ''
    Write-Host "Checking Key provider..." -ForegroundColor Yellow
    Write-Log -Message "Checking Key provider..."
    #Checking the KeyProvider:
    $KeyProvider = $DSReg | Select-String KeyProvider | Select-Object -first 1
    $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
    if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
        Write-Host "The KeyProvider is not configured correctly" -ForegroundColor Red
        Write-Log -Message "The KeyProvider is not configured correctly" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit

    }else{
        Write-Host "Certificate key provider configured correctly" -ForegroundColor Green
        Write-Log -Message "Certificate key provider configured correctly"
    }
    # Check other values.
    #Checking the certificate:
    $DID = $DSReg | Select-String DeviceId | Select-Object -first 1
    $DID = ($DID.ToString() -split ":")[1].Trim()
    $DTP = $DSReg | Select-String Thumbprint | Select-Object -first 1
    $DTP = ($DTP.ToString() -split ":")[1].Trim()
    Write-Host ''
    Write-Host "Checking device certificate configuration..." -ForegroundColor Yellow
    Write-Log -Message "Checking device certificate configuration..."
    CheckCert -DeviceID $DID -DeviceThumbprint $DTP
    CheckDeviceHealth $DID
    
    Write-Host ''
    Write-Host "Testing device dual state..." -ForegroundColor Yellow
    Write-Log -Message "Testing device dual state..."
    $HAADJTID = $DSReg | Select-String TenantId | Select-Object -first 1
    $HAADJTID = ($HAADJTID.tostring() -split ":")[1].trim()
    $WPJTID = $DSReg | Select-String WorkplaceTenantId | Select-Object -first 1
    $WPJTID = ($WPJTID.tostring() -split ":")[1].trim()
    $WPJ = $DSReg | Select-String WorkplaceJoined
    $WPJ = ($WPJ.tostring() -split ":")[1].trim()
    if (($WPJ -eq "YES") -and ($HAADJTID -eq $WPJTID)){
        Write-Host "Test failed: The device is in dual state" -ForegroundColor Red
        Write-Log -Message "Test failed: The device is in dual state" -Level WARN
        Write-Host ''
        Write-Host "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Microsoft Entra Registered state manually before enablingMicrosoft Entra hybrid joined by disconnecting the user from Access Work or School Account" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Microsoft Entra Registered state manually before enablingMicrosoft Entra hybrid joined by disconnecting the user from Access Work or School Account"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }elseif ($WPJ -ne "YES"){
        #Check if there is a token inside the path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com
        if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
            Write-Host "Test failed: The device is in dual state" -ForegroundColor Red
            Write-Log -Message "Test failed: The device is in dual state" -Level WARN
            Write-Host ''
            Write-Host "Recommended action: remove the registry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: remove the registry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Test passed: The device is not in dual state" -ForegroundColor Green
            Write-Log -Message "Test passed: The device is not in dual state"
        }
    }
    Write-Host ''
    Write-Host ''
    Write-Host "The device is connected to Microsoft Entra ID as Microsoft Entra hybrid joined, and it is in healthy state" -ForegroundColor Green
    Write-Log -Message "The device is connected to Microsoft Entra ID as Microsoft Entra hybrid joined, and it is in healthy state"
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''      
}

Function NewFunAAD{
    #The device is Microsoft Entra join
    $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host $hostname "device is joined to Microsoft Entra tenant:" $TenantName -ForegroundColor Green
    Write-Log -Message "$hostname device is joined to Microsoft Entra tenant: $TenantName"
    Write-Host ''
    Write-Host "Checking Key provider..." -ForegroundColor Yellow
    Write-Log -Message "Checking Key provider..."
    #Checking the KeyProvider:
    $KeyProvider = $DSReg | Select-String KeyProvider | Select-Object -first 1
    $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
    if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
        Write-Host "The KeyProvider is not configured correctly" -ForegroundColor Red
        Write-Log -Message "The KeyProvider is not configured correctly" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to performMicrosoft Entra hybrid joined procedure again"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }else{
        Write-Host "Certificate key provider configured correctly" -ForegroundColor Green
        Write-Log -Message "Certificate key provider configured correctly"
    }
    # Check other values.

    #Checking the certificate:
    $DID = $DSReg | Select-String DeviceId | Select-Object -first 1
    $DID = ($DID.ToString() -split ":")[1].Trim()
    $DTP = $DSReg | Select-String Thumbprint | Select-Object -first 1
    $DTP = ($DTP.ToString() -split ":")[1].Trim()
    Write-Host ''
    Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
    Write-Log -Message "Checking the device certificate configuration..."
    CheckCert -DeviceID $DID -DeviceThumbprint $DTP
    #Check the device status on AAD:
    CheckDeviceHealth $DID $true
    
    Write-Host ''
    Write-Host ''
    Write-Host "The device is connected successfully to Microsoft Entra ID as Microsoft Entra joined device, and it is in healthy state" -ForegroundColor Green
    Write-Log -Message "The device is connected successfully to Microsoft Entra ID as Microsoft Entra joined device, and it is in healthy state"
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''        
}

Function NewFunWPJ{
    #The device is Microsoft Entra join
    $TenantName = $DSReg | Select-String WorkplaceTenantName 
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host $hostname "device is connected to Microsoft Entra tenant:" $TenantName "as Microsoft Entra Registered device" -ForegroundColor Green
    Write-Log -Message "$hostname device is connected to Microsoft Entra tenant: $TenantName as Microsoft Entra Registered device"
    # Check other values.
    #Checking the certificate:
    $DID = $DSReg | Select-String WorkplaceDeviceId
    $DID = ($DID.ToString() -split ":")[1].Trim()
    $DTP = $DSReg | Select-String WorkplaceThumbprint
    $DTP = ($DTP.ToString() -split ":")[1].Trim()
       
    Write-Host ''
    Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
    Write-Log -Message "Checking the device certificate configuration..."
    CheckUserCert -DeviceID $DID -DeviceThumbprint $DTP

    #Check the device status on AAD:
    CheckDeviceHealth $DID $true

    Write-Host ''
    Write-Host ''
    Write-Host "The device is connected successfully to Microsoft Entra ID as Microsoft Entra Registered device, and it is in healthy state" -ForegroundColor Green
    Write-Log -Message "The device is connected successfully to Microsoft Entra ID as Microsoft Entra Registered device, and it is in healthy state"
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''        
}

Function DJ++{
        #Check OS version:
        Write-Host ''
        Write-Host "Checking OS version..." -ForegroundColor Yellow
        Write-Log -Message "Checking OS version..."
        $OSVersoin = ([environment]::OSVersion.Version).major
        if ($OSVersoin -ge 10){
        Write-Host "Device has current OS version." -ForegroundColor Green
        Write-Log -Message "Device has current OS version."
        #Check dsregcmd status.
        $DSReg = dsregcmd /status

        Write-Host ''
        Write-Host "Checking if the device joined to the local domain..." -ForegroundColor Yellow
        Write-Log -Message "Checking if the device joined to the local domain..."
        $DJ = $DSReg | Select-String DomainJoin
        $DJ = ($DJ.tostring() -split ":")[1].trim()
        if ($DJ -ne "YES"){
            $hostname = hostname
            Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow
            Write-Log -Message "$hostname device is NOT joined to the local domain" -Level ERROR
            Write-Host ''
            Write-Host "Checking if the device joined to Microsoft Entra ID..." -ForegroundColor Yellow
            Write-Log -Message "Checking if the device joined to Microsoft Entra ID..."
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
                #The device is not joined to AAD:
                Write-Host $hostname "device is NOT joined to Microsoft Entra ID" -ForegroundColor Yellow
                Write-Log -Message "$hostname device is NOT joined to Microsoft Entra ID" -Level ERROR
                Write-Host ''
                Write-Host "Checking if the device is Microsoft Entra Registered..." -ForegroundColor Yellow
                Write-Log -Message "Checking if the device is Microsoft Entra Registered..."
                $WPJ = $DSReg | Select-String WorkplaceJoined
                $WPJ = ($WPJ.tostring() -split ":")[1].trim()
                if ($WPJ -ne "YES"){
                    #The device is not WPJ:
                    Write-Host $hostname "device is NOT Microsoft Entra Registered" -ForegroundColor Yellow
                    Write-Log -Message "$hostname device is NOT Microsoft Entra Registered" -Level ERROR
                    Write-Host ''
                    Write-Host $hostname "The device is not connected to Microsoft Entra ID" -ForegroundColor Red
                    Write-Log -Message "$hostname The device is not connected to Microsoft Entra ID" -Level ERROR
                    Write-Host ''
                    Write-Host ''
                    Write-Host "Script completed successfully." -ForegroundColor Green
                    Write-Log -Message "Script completed successfully."
                    Write-Host ''
                    Write-Host ''
                    #exit
                }else{
                    #The device is WPJ
                    NewFunWPJ
                }

            }else{
                #Device joined to AAD
                NewFunAAD
            }
        }else{
            #The device is joined to the local domain.
            $DomainName = $DSReg | Select-String DomainName 
            $DomainName =($DomainName.tostring() -split ":")[1].trim()
            $hostname = hostname
            Write-Host $hostname "device is joined to the local domain:" $DomainName -ForegroundColor Green
            Write-Log -Message "$hostname device is joined to the local domain: $DomainName"
    
            #Checking if the device connected to AzureAD
            Write-Host ''
            Write-Host "Checking if the device is connected to AzureAD..." -ForegroundColor Yellow
            Write-Log -Message "Checking if the device is connected to AzureAD..."
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
            #The device is not connected to AAD:
            Write-Host $hostname "device is NOT connected to Microsoft Entra ID" -ForegroundColor Red
            Write-Log -Message "$hostname device is NOT connected to Microsoft Entra ID"
            Write-Host ''
            Write-Host "Recommended action: Run 'dsregcmd /join' command as admin to performMicrosoft Entra hybrid joined procedure. To troubleshoot hybrid device registration, re-run the tool and select option #3. If the issue still persists, check the possible causes on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Run 'dsregcmd /join' command as admin to performMicrosoft Entra hybrid joined procedure. To troubleshoot hybrid device registration, re-run the tool and select option #3. If the issue still persists, check the possible causes on the article: http://www.microsoft.com/aadjerrors"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
            }else{
                NewFun
            }
        }
    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version" -ForegroundColor Red
        Write-Log -Message "The device has a Windows down-level OS version" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }
}

Function DJ++TS{
    $ErrorActionPreference= 'silentlycontinue'
    #Check PSAdmin
    Write-Host ''
    Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow 
    Write-Log -Message "Testing if PowerShell running with elevated privileges..."
    if (PSasAdmin){
        # PS running as admin.
        Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green
        Write-Log -Message "PowerShell is running with elevated privileges"
    }else{
        Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red
        Write-Log -Message "PowerShell is NOT running with elevated privileges" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: This test needs to be running with elevated privileges" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: This test needs to be running with elevated privileges"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }

    #Check OS version:
    Write-Host ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    Write-Log -Message "Testing OS version..."
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        $OSVer = (([environment]::OSVersion).Version).ToString()
        Write-Host "Test passed: device has current OS version ($OSVer)" -ForegroundColor Green
        Write-Log -Message "Test passed: device has current OS version ($OSVer)"
    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
        Write-Log -Message "The device has a Windows down-level OS version." -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above."
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }


    #Check dsregcmd status.
    $DSReg = dsregcmd /status

    Write-Host ''
    Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device joined to the local domain..."
    $DJ = $DSReg | Select-String DomainJoin
    $DJ = ($DJ.tostring() -split ":")[1].trim()
    if ($DJ -ne "YES"){
        $hostname = hostname
        Write-Host $hostname "Test failed: device is NOT joined to the local domain" -ForegroundColor Red
        Write-Log -Message "Test failed: device is NOT joined to the local domain" -Level ERROR
        Write-Host ''
        Write-Host "Recommended action: You need to join the device to the local domain in order to perform Microsoft Entra hybrid joined." -ForegroundColor Yellow
        Write-Log -Message "Recommended action: You need to join the device to the local domain in order to perform Microsoft Entra hybrid joined."
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }else{
        #The device is joined to the local domain.
        $DomainName = $DSReg | Select-String DomainName 
        $DomainName =($DomainName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host "Test passed:" $hostname "device is joined to the local domain:" $DomainName -ForegroundColor Green
        Write-Log -Message "Test passed: $hostname device is joined to the local domain: $DomainName"
    }    

    #Checking if the device connected to AzureAD
    Write-Host ''
    Write-Host "Testing if the device is connected to AzureAD..." -ForegroundColor Yellow
    Write-Log -Message "Testing if the device is connected to AzureAD..."
    $AADJ = $DSReg | Select-String AzureAdJoined
    $AADJ = ($AADJ.tostring() -split ":")[1].trim()
    if ($AADJ -ne "YES"){
        #The device is not connected to AAD:
        ### perform DJ++ (all other tests should be here)
        Write-Host "Test failed:" $hostname "device is NOT connected to Microsoft Entra ID" -ForegroundColor Red
        Write-Log -Message "Test failed: $hostname device is NOT connected to Microsoft Entra ID" -Level ERROR
        #Check Automatic-Device-Join Task
        Write-Host ''
        Write-Host "Testing Automatic-Device-Join task scheduler..." -ForegroundColor Yellow
        Write-Log -Message "Testing Automatic-Device-Join task scheduler..."
        $TaskState=((schtasks.exe /query /tn "\Microsoft\Windows\Workplace Join\Automatic-Device-Join")[4].Trim() -split " ")[-1]
        if (($TaskState -ne 'Ready') -and ($TaskState -ne 'Bereit')){
            Write-Host "Test failed: Automatic-Device-Join task scheduler is not ready" -ForegroundColor Red
            Write-Log -Message "Test failed: Automatic-Device-Join task scheduler is not ready" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: please enable 'Automatic-Device-Join' task from 'Task Scheduler Library\Microsoft\Windows\Workplace Join'." -ForegroundColor Yellow
            Write-Log -Message "Recommended action: please enable 'Automatic-Device-Join' task from 'Task Scheduler Library\Microsoft\Windows\Workplace Join'."
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Test passed: Automatic-Device-Join task scheduler is ready" -ForegroundColor Green
            Write-Log -Message "Test passed: Automatic-Device-Join task scheduler is ready"
        }

        VerifySCP

        #Check connectivity to DC if it has not performed yet
        if ($global:DCTestPerformed=$false){
            #Check connectivity to DC
            $global:DCTestPerformed=$true
            Write-Host ''
            Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
            Write-Log -Message "Testing Domain Controller connectivity..."
            $DCName=""
            $DCTest=nltest /dsgetdc:
            $DCName = $DCTest | Select-String DC | Select-Object -first 1
            $DCName =($DCName.tostring() -split "DC: \\")[1].trim()
            if (($DCName.length) -eq 0){
                Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red
                Write-Log -Message "Test failed: connection to Domain Controller failed" -Level ERROR
                Write-Host ''
                Write-Host "Recommended action: Make sure that the device has a line of sight connection to the Domain controller" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: Make sure that the device has a line of sight connection to the Domain controller"
                Write-Host ''
                Write-Host ''
                Write-Host "Script completed successfully." -ForegroundColor Green
                Write-Log -Message "Script completed successfully."
                Write-Host ''
                Write-Host ''
                exit        
            }else{
                Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green
                Write-Log -Message "Test passed: connection to Domain Controller succeeded"
            }
        }
    
        #Checking Internet connectivity
        Test-DevRegConnectivity $true | Out-Null

        ###conn

        #Testing if the device synced (with managed domain)
        Write-Host ''
        Write-Host "Checking domain authentication type..." -ForegroundColor Yellow
        Write-Log -Message "Checking domain authentication type..."
        #Check if URL status code is 200
        #check through proxy if exist
        #run under sys account
        $UserRealmJson=""
        $UserRelmURL = "https://login.microsoftonline.com/common/UserRealm/?user=$global:TenantName&api-version=1.0"
        if (($global:ProxyServer -eq "NoProxy") -or ($global:ProxyServer -eq "winInet")){
            $PSScript = "Invoke-WebRequest -uri '$UserRelmURL' -UseBasicParsing"
            $UserRealmJson = RunPScript -PSScript $PSScript #| Out-Null
         }else{
            $PSScript = "Invoke-WebRequest -uri '$UserRelmURL' -UseBasicParsing -Proxy $global:ProxyServer"
            $UserRealmJson = RunPScript -PSScript $PSScript #| Out-Null
         }
         #Test failed with both winHTTP & winInet
        if(!($UserRealmJson)){
            Write-Host "Test failed: Could not check domain authentication type." -ForegroundColor Red
            Write-Log -Message "Test failed: Could not check domain authentication type." -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Make sure the device has Internet connectivity." -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Make sure the device has Internet connectivity."
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit  
        }

        $UserRealm = $UserRealmJson.Content | ConvertFrom-Json
        $global:UserRealmMEX = $UserRealm.federation_metadata_url
        $global:FedProtocol = $UserRealm.federation_protocol
        #Check if the domain is Managed
        if ($UserRealm.account_type -eq "Managed"){
            #The domain is Managed
            Write-Host "The configured domain is Managed" -ForegroundColor Green
            Write-Log -Message "The configured domain is Managed"
            SyncJoinCheck

        }else{
        #The domain is federated
        Write-Host "The configured domain is Federated" -ForegroundColor Green
        Write-Log -Message "The configured domain is Federated"
        #Testing Federation protocol
        Write-Host ''
        Write-Host "Testing WSTrust Protocol..." -ForegroundColor Yellow
        Write-Log -Message "Testing WSTrust Protocol..."
        if ($global:FedProtocol -ne "WSTrust"){
            #Not WSTrust
            Write-Host "Test failed: WFTrust protocol is not enabled on federation service configuration." -ForegroundColor Red
            Write-Log -Message "Test failed: WFTrust protocol is not enabled on federation service configuration." -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: Make sure that your federation service supports WSTrust protocol, and WSTrust is enabled on Microsoft Entra ID federated domain configuration." -ForegroundColor Yellow
            Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
            Write-Log -Message "Recommended action: Make sure that your federation service supports WSTrust protocol, and WSTrust is enabled on Microsoft Entra ID federated domain configuration.`n                                 Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join."
            SyncJoinCheck $true
        }else{
            #WSTrust enabled
            Write-Host "Test passed: WSTrust protocol is enabled on federation service configuration." -ForegroundColor Green
            Write-Log -Message "Test passed: WSTrust protocol is enabled on federation service configuration."
    
            #Testing MEX URL
            Write-Host ''
            Write-Host "Testing Metadata Exchange URI (MEX) URL..." -ForegroundColor Yellow
            Write-Log -Message "Testing Metadata Exchange URI (MEX) URL..."
            $ErrorActionPreference = "SilentlyContinue"
            $WebResponse=""

            #Check if FSName bypassed by proxy
            $ADFSName=$global:UserRealmMEX -Split "https://"
            $ADFSName=$ADFSName[1] -Split "/"
            $FSName=$ADFSName[0]
            $ADFSName=$FSName -split "\."
            $ADFSName[0], $ADFSNameRest=$ADFSName
            $ADFSNameAll = $ADFSNameRest -join '.'
            $ADFSNameAll = "*."+$ADFSNameAll
            $global:FedProxy= $global:Bypass.Contains($FSName) -or $global:Bypass.Contains($ADFSNameAll)

            #If there is no proxy, or FSName bypassed by proxy
            if ((($global:ProxyServer -eq "NoProxy") -or ($global:ProxyServer -eq "winInet")) -or ($global:FedProxy)){
                $PSScript = "Invoke-WebRequest -uri $global:UserRealmMEX -UseBasicParsing"
                $WebResponse = RunPScript -PSScript $PSScript
            }else{
                $PSScript = "Invoke-WebRequest -uri $global:UserRealmMEX -UseBasicParsing -Proxy $global:ProxyServer"
                $WebResponse = RunPScript -PSScript $PSScript
            }

            if ((($WebResponse.Content).count) -eq 0 ){
                #Not accessible
                Write-Host "Test failed: MEX URL is not accessible." -ForegroundColor Red
                Write-Log -Message "Test failed: MEX URL is not accessible."
                Write-Host ''
                Write-Host "Recommended action: Make sure the MEX URL $global:UserRealmMEX is accessible." -ForegroundColor Yellow
                Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
                Write-Log -Message "Recommended action: Make sure the MEX URL $global:UserRealmMEX is accessible.`n                                 Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join."
                SyncJoinCheck $true
            }else{
                #MEX is accessible
                Write-Host "Test passed: MEX URL '$global:UserRealmMEX' is accessible." -ForegroundColor Green
                Write-Log -Message "Test passed: MEX URL '$global:UserRealmMEX' is accessible."
                ''
                Write-Host "Testing windowstransport endpoints on your federation service..." -ForegroundColor Yellow
                Write-Log -Message "Testing windowstransport endpoints on your federation service..."
                $WebResponseXMLContent = [xml]$WebResponse.Content 
                foreach ($Object in $WebResponseXMLContent.definitions.service.port) {
                    if ($Object.EndpointReference.Identity.xmlns -eq "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity"){
                        $WTransportURL = $Object.EndpointReference.Address
                    }
                }
                if($WTransportURL){
                    Write-Host "Test passed: windowstransport endpoint is enabled on your federation service as the following:" -ForegroundColor Green
                    $WTransportURL
                    Write-Log -Message "Test passed: windowstransport endpoint is enabled on your federation service as the following: `n                                 $WTransportURL"
                    #Testing if the federation service is ADFS:
                    if ($WTransportURL.contains('/adfs/')){
                        # Federation service is ADFS
                        ''
                        Write-Host "Testing device authentication against your federation service..." -ForegroundColor Yellow
                        Write-Log -Message "Testing device authentication against your federation service..."
                        if ($WTransportURL.contains('/2005/')){
                            $Envelope = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"><s:Header><wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To s:mustUnderstand="1">'+$WTransportURL+'</wsa:To><wsa:MessageID>urn:uuid:65925CF8-DE9C-43DA-B193-66575B649631</wsa:MessageID></s:Header><s:Body><wst:RequestSecurityToken Id="RST0"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>urn:federation:MicrosoftOnline</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType></wst:RequestSecurityToken></s:Body></s:Envelope>'
                        }elseif ($WTransportURL.contains('/13/')){
                            $Envelope = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action><a:MessageID>urn:uuid:DD679E17-7902-4EEA-AA45-071CFFE27502</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">'+$WTransportURL+'</a:To></s:Header><s:Body><trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><a:EndpointReference><a:Address>urn:federation:MicrosoftOnline</a:Address></a:EndpointReference></wsp:AppliesTo><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType></trust:RequestSecurityToken></s:Body></s:Envelope>'
                        }
                        $Body = [String]::Format($Envelope, $WTransportURL, "urn:federation:MicrosoftOnline")
                        #If there is no proxy, or FSName bypassed by proxy
                        if ((($global:ProxyServer -eq "NoProxy") -or ($global:ProxyServer -eq "winInet")) -or ($global:FedProxy)){
                            $PSScript = "Invoke-WebRequest "+$WTransportURL+" -Method Post -Body '"+$Body+"' -ContentType 'application/soap+xml; charset=utf-8' -UseDefaultCredentials -UseBasicParsing"
                            $webresp = RunPScript -PSScript $PSScript
                        }else{
                            $PSScript = "Invoke-WebRequest "+$WTransportURL+" -Method Post -Body '"+$Body+"' -ContentType 'application/soap+xml; charset=utf-8' -UseDefaultCredentials -UseBasicParsing -Proxy "+$global:ProxyServer
                            $webresp = RunPScript -PSScript $PSScript
                        }
                        $tokenXml = [xml]$webresp.Content
                        $Token=$tokenXml.OuterXml
                        if ($Token.Contains("FailedAuthentication")){
                            Write-Host "Test failed: Device authentication failed against your federation service" -ForegroundColor Red
                            Write-Log -Message "Test failed: Device authentication failed against your federation service" -Level ERROR
                            Write-Host ''
                            Write-Host "Recommended action: Make sure that your federation service allows non-interactive/device authenticaion." -ForegroundColor Yellow
                            Write-Host "Important Note: if you force MFA, make sure to exclude it for non-interactive/device authenticaion." -ForegroundColor Yellow
                            Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
                            Write-Log -Message "Recommended action: Make sure that your federation service allows non-interactive/device authenticaion.`n                                 Important Note: if you force MFA, make sure to exclude it for non-interactive/device authenticaion.`n                                 Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join."
                            SyncJoinCheck $true
                        }else{
                            Write-Host "Test passed: Device authenticated successfully." -ForegroundColor Green
                            Write-Log -Message "Test passed: Device authenticated successfully."
                            ''
                            Write-Host "Testing Device registration claim rules..." -ForegroundColor Yellow
                            Write-Log -Message "Testing device registration claim rules..."
                            $fedjoinfailed = $false
                            if ($Token.Contains("primarysid")){
                                Write-Host "Test passed: 'primarysid' claim is configured." -ForegroundColor Green
                                Write-Log -Message "Test passed: 'primarysid' claim is configured."
                            }else{
                                Write-Host "Test failed: 'primarysid' claim is NOT configured." -ForegroundColor Red
                                Write-Log -Message "Test failed: 'primarysid' claim is NOT configured." -Level ERROR
                                $fedjoinfailed = $true
                            }
                            if ($Token.Contains("accounttype")){
                                Write-Host "Test passed: 'accounttype' claim is configured." -ForegroundColor Green
                                Write-Log -Message "Test passed: 'accounttype' claim is configured."
                            }else{
                                Write-Host "Test failed: 'accounttype' claim is NOT configured." -ForegroundColor Red
                                Write-Log -Message "Test failed: 'accounttype' claim is NOT configured."
                                $fedjoinfailed = $true
                            }
                            if ($Token.Contains("ImmutableID")){
                                Write-Host "Test passed: 'ImmutableID' claim is configured." -ForegroundColor Green
                                Write-Log -Message "Test passed: 'ImmutableID' claim is configured."
                            }else{
                                Write-Host "Test failed: 'ImmutableID' claim is NOT configured." -ForegroundColor Red
                                Write-Log -Message "Test failed: 'ImmutableID' claim is NOT configured." -Level ERROR
                                $fedjoinfailed = $true
                            }
                            if ($Token.Contains("onpremobjectguid")){
                                Write-Host "Test passed: 'onpremobjectguid' claim is configured." -ForegroundColor Green
                                Write-Log -Message "Test passed: 'onpremobjectguid' claim is configured."
                            }else{
                                Write-Host "Test failed: 'onpremobjectguid' claim is NOT configured." -ForegroundColor Red
                                Write-Log -Message "Test failed: 'onpremobjectguid' claim is NOT configured." -Level ERROR
                                $fedjoinfailed = $true
                            }

                            if ($fedjoinfailed){
                                ''
                                Write-Host "Test failed: Device registration claim rules are NOT configured correctly." -ForegroundColor Red
                                Write-Host "Recommended action: Make sure that claim rules are configured on 'Microsoft Office 365' Relying Part Trust. For more info, see https://docs.microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-manual" -ForegroundColor Yellow
                                Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
                                Write-Log -Message "Test failed: Device registration claim rules are NOT configured correctly." -Level ERROR
                                Write-Log -Message "Recommended action: Make sure that claim rules are configured on 'Microsoft Office 365' Relying Part Trust. For more info, see https://docs.microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-manual `n                                 Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -Level WARN
                                SyncJoinCheck $true
                            }else{
                                ''
                                Write-Host "Test passed: Device registration claim rules are configured correctly." -ForegroundColor Green
                                Write-Log -Message "Test passed: Device registration claim rules are configured correctly."
                            }

                        }
                    }
    
                }else{
                    Write-Host "Test failed: windowstransport endpoints are disabled on your federation service" -ForegroundColor Red
                    Write-Log -Message "Test failed: windowstransport endpoints are disabled on your federation service" -Level ERROR
                    Write-Host ''
                    Write-Host "Recommended action: Make sure that windowstransport endpoints are enabled on your federation service." -ForegroundColor Yellow
                    Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
                    Write-Log -Message "Recommended action: Make sure that windowstransport endpoints are enabled on your federation service. `n                                 Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join."
                    SyncJoinCheck $true
                }

                ###
            }

        }

    }   
        #Check DevReg app
        ConnecttoAzureAD
        Test-DevRegApp
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully. You can start Microsoft Entra hybrid joined registration process." -ForegroundColor Green
        Write-Log -Message "Script completed successfully. You can start Microsoft Entra hybrid joined registration process."
        Write-Host ''
        Write-Host ''
        exit

    }else{
        #The device is Microsoft Entra hybrid joined
        $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
        $TenantName =($TenantName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host "Test passed:" $hostname "device is joined to Microsoft Entra tenant:" $TenantName -ForegroundColor Green
        Write-Log -Message "Test passed: $hostname device is joined to Microsoft Entra tenant: $TenantName"
    }

    #CheckMSOnline

    #Check the device status on AAD:
    $DID = $DSReg | Select-String DeviceId  | Select-Object -first 1
    $DID = ($DID.ToString() -split ":")[1].Trim()
    CheckDeviceHealth $DID

    Write-Host ''
    Write-Host "Testing device dual state..." -ForegroundColor Yellow
    Write-Log -Message "Testing device dual state..."
    $HAADJTID = $DSReg | Select-String TenantId | Select-Object -first 1
    $HAADJTID = ($HAADJTID.tostring() -split ":")[1].trim()
    $WPJTID = $DSReg | Select-String WorkplaceTenantId | Select-Object -first 1
    $WPJTID = ($WPJTID.tostring() -split ":")[1].trim()
    $WPJ = $DSReg | Select-String WorkplaceJoined
    $WPJ = ($WPJ.tostring() -split ":")[1].trim()
    if (($WPJ -eq "YES") -and ($HAADJTID -eq $WPJTID)){
        Write-Host "Test failed: The device is in dual state" -ForegroundColor Red
        Write-Log -Message "Test failed: The device is in dual state" -Level WARN
        Write-Host ''
        Write-Host "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Microsoft Entra Registered state manually before enablingMicrosoft Entra hybrid joined by disconnecting the user from Access Work or School Account" -ForegroundColor Yellow
        Write-Log -Message "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Microsoft Entra Registered state manually before enablingMicrosoft Entra hybrid joined by disconnecting the user from Access Work or School Account"
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Log -Message "Script completed successfully."
        Write-Host ''
        Write-Host ''
        exit
    }elseif ($WPJ -ne "YES"){
        #Check if there is a token inside the path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com
        if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
            Write-Host "Test failed: The device is in dual state" -ForegroundColor Red
            Write-Log -Message "Test failed: The device is in dual state" -Level WARN
            Write-Host ''
            Write-Host "Recommended action: remove the registry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'" -ForegroundColor Yellow
            Write-Log -Message "Recommended action: remove the registry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'"
            Write-Host ''
            Write-Host ''
            Write-Host "Script completed successfully." -ForegroundColor Green
            Write-Log -Message "Script completed successfully."
            Write-Host ''
            Write-Host ''
            exit
        }else{
            Write-Host "Test passed: The device is not in dual state" -ForegroundColor Green
            Write-Log -Message "Test passed: The device is not in dual state"
        }
    }
    Write-Host ''
    Write-Host ''
    Write-Host "The device is connected to Microsoft Entra ID as Microsoft Entra hybrid joined device, and it is in healthy state." -ForegroundColor Green
    Write-Log -Message "The device is connected to Microsoft Entra ID as Microsoft Entra hybrid joined device, and it is in healthy state."
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''    
}
$ErrorActionPreference= 'silentlycontinue'
$global:DomainAuthType=""
$global:MEXURL=""
$global:MEXURLRun=$true
$global:DCTestPerformed=$false
$global:Bypass=""
$global:login=$false
$global:device=$false
$global:enterprise=$false
$global:ProxyServer=""

cls
'==========================================================='
Write-Host '          Device Registration Troubleshooter Tool          ' -ForegroundColor Green 
'==========================================================='
Write-Host ''
Write-Host "Please provide any feedback, comment or suggestion" -ForegroundColor Yellow
Write-Host
Write-Host "Enter (1) to troubleshoot Microsoft Entra Register" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (2) to troubleshoot Microsoft Entra join device" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (3) to troubleshoot Microsoft Entra hybrid join" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (4) to verify Service Connection Point (SCP)" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (5) to verify the health status of the device" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (6) to Verify Primary Refresh Token (PRT)" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (7) to collect the logs" -ForegroundColor Green
Write-Host ''
Write-Host "Enter (Q) to Quit" -ForegroundColor Green
Write-Host ''
Add-Content ".\DSRegTool.log" -Value "==========================================================" -ErrorAction SilentlyContinue
if($Error[0].Exception.Message -ne $null){
    if($Error[0].Exception.Message.Contains('denied')){
        Write-Host "Was not able to create log file." -ForegroundColor Yellow
        Write-Host ''
    }else{
        Write-Host "DSRegTool log file has been created." -ForegroundColor Yellow
        Write-Host ''
    }
}else{
    Write-Host "DSRegTool log file has been created." -ForegroundColor Yellow
    Write-Host ''
}
Add-Content ".\DSRegTool.log" -Value "==========================================================" -ErrorAction SilentlyContinue
Write-Log -Message "DSRegTool 4.0 has started"
$msg="Device Name : " + (Get-Childitem env:computername).value
Write-Log -Message $msg

Add-Type -AssemblyName System.DirectoryServices.AccountManagement            
$UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
If ($UserPrincipal.ContextType -ne "Machine"){
    $global:UserUPN=whoami /upn
}

$msg="User Account: " + (whoami) +", UPN: "+$global:UserUPN
Write-Log -Message $msg

$Num =Write-Host ''
$Num = Read-Host -Prompt "Please make a selection, and press Enter" 

While(($Num -ne '1') -AND ($Num -ne '2') -AND ($Num -ne '3') -AND ($Num -ne '4') -AND ($Num -ne '5') -AND ($Num -ne '6') -AND ($Num -ne '7') -AND ($Num -ne 'Q')){

$Num = Read-Host -Prompt "Invalid input. Please make a correct selection from the above options, and press Enter" 

}

if($Num -eq '1'){
    Write-Host ''
    Write-Host "troubleshoot Microsoft Entra Register option has been chosen"
    Write-Log -Message "troubleshoot Microsoft Entra Register option has been chosen"
    Write-Host ''
    DSRegToolStart 
    WPJTS
}elseif($Num -eq '2'){
    Write-Host ''
    Write-Host "troubleshoot Microsoft Entra join device option has been chosen"
    Write-Log -Message "troubleshoot Microsoft Entra join device option has been chosen"
    Write-Host ''
    DSRegToolStart
    AADJ
}elseif($Num -eq '3'){
    Write-Host ''
    Write-Host "TroubleshootMicrosoft Entra hybrid joined option has been chosen"
    Write-Log -Message "TroubleshootMicrosoft Entra hybrid joined option has been chosen"
    Write-Host ''
    DSRegToolStart
    DJ++TS
}elseif($Num -eq '4'){
    Write-Host ''
    Write-Host "Verify Service Connection Point (SCP) has been chosen"
    Write-Log -Message "Verify Service Connection Point (SCP) has been chosen"
    Write-Host ''
    DSRegToolStart
    VerifySCP
    Write-Host ''
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green
    Write-Log -Message "Script completed successfully."
    Write-Host ''
    Write-Host ''   
}elseif($Num -eq '5'){
    Write-Host ''
    Write-Host "Verify the health status of the device option has been chosen"
    Write-Log -Message "Verify the health status of the device option has been chosen"
    Write-Host ''
    DSRegToolStart
    DJ++
}elseif($Num -eq '6'){
    Write-Host ''
    Write-Host "Verify Primary Refresh Token (PRT) option has been chosen"
    Write-Log -Message "Verify Primary Refresh Token (PRT) option has been chosen"
    Write-Host ''
    DSRegToolStart
    CheckPRT
}elseif($Num -eq '7'){
    Write-Host ''
    Write-Host "Collect the logs option has been chosen"
    Write-Log -Message "Collect the logs option has been chosen"
    Write-Host ''
    DSRegToolStart
    LogsCollection
}else{
    Write-Host ''
    Write-Host "Quit option has been chosen"
    Write-Log -Message "Quit option has been chosen"
    Write-Host ''
}
# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDlq+A4m3PJUxbv
# iJz2qB2NZ5Fi7B62O8xzqVFgk5vio6CCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDl52AEby/9QjkGOvDQnx35J
# OURyDV6TbCtCzNOWUQeGMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0B
# AQEFAASCAQDKAh6hpd4YeM81zq3oFChpcZeyZqw0Mp2uCzSTe0tvItwU7AlnPXg3
# FQcBHH5fkXjNnQLN74MSNt0fTy8qrF6eSuq3qVDqidq98c6Zz1nQ3LuYnah4uAx3
# mym8T0kSQq8UCKyfGmFjZoeA5jUAntFeisqW36lLv4dFykT7kFObqRSEdYGlbk59
# YdVrykS0/fylEn51jmTGttyBnHa5sIX1YomEDIYX5HZ3ZpK/LWaxyc+sLq8Wm6YC
# Uqh4zreMh2bnF/aD6WxIGqwuhnYKwLB59A6z3CJlpl5GQhcq3a1tXud3EQLcS3/O
# w+w2ZJ5Xq0rm5KLIEhcNGmjQ6rU3lYyqoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIB2iFknI9uYwtAOlgS1SIbYp87A5IstEzkQSVOx0yXrCAgZluqP0
# rzUYEzIwMjQwMjA0MDkxNTA5LjcxMVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAeKZmZXx3OMg6wABAAAB4jAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA3MjVaFw0yNTAxMTAxOTA3MjVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEt
# NEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtWO1mFX6QWZvxwpCmDab
# OKwOVEj3vwZvZqYa9sCYJ3TglUZ5N79AbMzwptCswOiXsMLuNLTcmRys+xaL1alX
# CwhyRFDwCRfWJ0Eb0eHIKykBq9+6/PnmSGXtus9DHsf31QluwTfAyamYlqw9amAX
# TnNmW+lZANQsNwhjKXmVcjgdVnk3oxLFY7zPBaviv3GQyZRezsgLEMmvlrf1JJ48
# AlEjLOdohzRbNnowVxNHMss3I8ETgqtW/UsV33oU3EDPCd61J4+DzwSZF7OvZPcd
# MUSWd4lfJBh3phDt4IhzvKWVahjTcISD2CGiun2pQpwFR8VxLhcSV/cZIRGeXMmw
# ruz9kY9Th1odPaNYahiFrZAI6aSCM6YEUKpAUXAWaw+tmPh5CzNjGrhzgeo+dS7i
# FPhqqm9Rneog5dt3JTjak0v3dyfSs9NOV45Sw5BuC+VF22EUIF6nF9vqduynd9xl
# o8F9Nu1dVryctC4wIGrJ+x5u6qdvCP6UdB+oqmK+nJ3soJYAKiPvxdTBirLUfJid
# K1OZ7hP28rq7Y78pOF9E54keJKDjjKYWP7fghwUSE+iBoq802xNWbhBuqmELKSev
# AHKqisEIsfpuWVG0kwnCa7sZF1NCwjHYcwqqmES2lKbXPe58BJ0+uA+GxAhEWQdk
# a6KEvUmOPgu7cJsCaFrSU6sCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBREhA4R2r7t
# B2yWm0mIJE2leAnaBTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA5FREMatVFNue
# 6V+yDZxOzLKHthe+FVTs1kyQhMBBiwUQ9WC9K+ILKWvlqneRrvpjPS3/qXG5zMjr
# Du1eryfhbFRSByPnACGc2iuGcPyWNiptyTft+CBgrf7ATAuE/U8YLm29crTFiiZT
# WdT6Vc7L1lGdKEj8dl0WvDayuC2xtajD04y4ANLmWDuiStdrZ1oI4afG5oPUg77r
# kTuq/Y7RbSwaPsBZ06M12l7E+uykvYoRw4x4lWaST87SBqeEXPMcCdaO01ad5TXV
# ZDoHG/w6k3V9j3DNCiLJyC844kz3eh3nkQZ5fF8Xxuh8tWVQTfMiKShJ537yzrU0
# M/7H1EzJrabAr9izXF28OVlMed0gqyx+a7e+79r4EV/a4ijJxVO8FCm/92tEkPrx
# 6jjTWaQJEWSbL/4GZCVGvHatqmoC7mTQ16/6JR0FQqZf+I5opnvm+5CDuEKIEDnE
# iblkhcNKVfjvDAVqvf8GBPCe0yr2trpBEB5L+j+5haSa+q8TwCrfxCYqBOIGdZJL
# +5U9xocTICufIWHkb6p4IaYvjgx8ScUSHFzexo+ZeF7oyFKAIgYlRkMDvffqdAPx
# +fjLrnfgt6X4u5PkXlsW3SYvB34fkbEbM5tmab9zekRa0e/W6Dt1L8N+tx3WyfYT
# iCThbUvWN1EFsr3HCQybBj4Idl4xK8EwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAWm5lp+nRuekl0iF+IHV3ylOiGb6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6Wm/VzAiGA8yMDI0MDIwNDE1NDYzMVoYDzIwMjQwMjA1MTU0NjMxWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDpab9XAgEAMAcCAQACAguHMAcCAQACAhGUMAoC
# BQDpaxDXAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAU5IWQKNu3fiNHWTb
# mN8csgZjtVZbwB3ZFr332l9ILkZSKzyqW2r7u7hFlMY/fwCe+mRw0PGz1kF8ShZA
# tMxXH6Dw01kTFS9IIEvWkB9ZigWp59hYXDVs+rx4NhdR5hGE5jeTk6QdmKw/AfGK
# Ur3L1SNtytCM+oXZVPEo8ER150AxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAeKZmZXx3OMg6wABAAAB4jANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCDH9YL5zwTBq/HGkMvQyxR48HJi5LmiYVnLv3pZrNGn6TCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EICuJKkoQ/Sa4xsFQRM4Ogvh3ktToj9uO5whmQ4kI
# j3//MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHi
# mZmV8dzjIOsAAQAAAeIwIgQgJJoWJzooAlwThj55XMsiTjdI1wz+Gm1zkaCS7u3l
# HBAwDQYJKoZIhvcNAQELBQAEggIArvOpqYMI8GVU3ydQgO16zwPNeCqsSUPeZB/U
# rvfTsoZD3AYiZ0l7oF71KG6ojpkVFGovd4+CtXeM8cEblXV6nxAH0TbOZnM+0hh1
# 31UyFCOTyf933HtePJF7Txucn43ReevsoR6XZapDE1nR77N4Pq/qTXrc1d27qnZV
# 8uFOTv5upf69bVqFY+7+U8XUNUQ4vMB+Ft/PUDo8359PBovcZa7HegurCPOyjDkJ
# OhDSrTsXOz70618d18Qffqyr+YYvMs5YK2V8n12NDjbfWBqWN6nzMAFPswYX/pD1
# 0QVMZM78xpTzm8JwKgKMFABv+/gF9NNInrYCkCUqELIdMvGGYFCxMAYA8ABfpzZb
# 1cvDBvOjOCv7ttC70swGGz4WmEnE5GUA2XxoDiGAaV36pgabjQuXd+er7LmySNIA
# kG20v0P/m/xkHEIDhjHi/DX9MVS1DU8YRDo30cg8UowHRLd4Lov61W6YD6Jn89Mp
# D7ZKiLUgx0JW8U7F7IQ6vuFjyewLwE016s6LScJPr5iBlLFffT3qpw3P8i8BNurn
# YbJDiZFPoWO6d/f5ps5yo/vrd242vckukXhPsDmr2h60dnTWEUa1i8kx4u0L9ZpX
# ml6e6mwRKzHrE25fy4Orz7bVdOHzUe6kgHnreL4C2sW3hYFNVY6MdYn1mexGWcAC
# YHmt37c=
# SIG # End signature block
