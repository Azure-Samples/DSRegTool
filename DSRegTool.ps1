<# 
 
.SYNOPSIS
    DSRegTool V2.1 PowerShell script.

.DESCRIPTION
    Device Registration Troubleshooter Tool is a PowerShell script that troubleshhot device registration common issues.

.AUTHOR:
    Mohammad Zmaili

.EXAMPLE
    .\DSRegTool.ps1

    Enter (1) to troubleshoot Azure AD Register

    Enter (2) to troubleshoot Azure AD Join device

    Enter (3) to troubleshoot Hybrid Azure AD Join

    Enter (4) to verify Service Connection Point (SCP)

    Enter (5) to verify the health status of the device

    Enter (6) to Verify Primary Refresh Token (PRT)

    Enter (7) to collect the logs

    Enter (Q) to Quit


#>

Function CheckePRT{
    ''
    Write-Host "Testing Enterprise PRT..." -ForegroundColor Yellow
    $ePRT = $DSReg | Select-String EnterprisePrt | select-object -First 1
    $ePRT = ($ePRT.tostring() -split ":")[1].trim()
    if ($ePRT -eq 'YES'){
        $hostname = hostname
        Write-Host $hostname "device does have Enterprise PRT" -ForegroundColor Green -BackgroundColor Black
    }else{
        $hostname = hostname
        Write-Host $hostname "device does NOT have Enterprise PRT" -ForegroundColor Yellow -BackgroundColor Black
    }

}

Function PSasAdmin{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function CheckPRT{
''
Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow
if (PSasAdmin){
    # PS running as admin.
    Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: This test needs to be running with normal privileges" -ForegroundColor Yellow -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
    Write-Host "PowerShell is running with normal privileges" -ForegroundColor Green -BackgroundColor Black
}


    #Check OS version:
    ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
        ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }

    #Check dsregcmd status.
    $DSReg = dsregcmd /status

    ''
    Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
    $DJ = $DSReg | Select-String DomainJoin
    $DJ = ($DJ.tostring() -split ":")[1].trim()
    if ($DJ -ne "YES"){
        $hostname = hostname
        Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow -BackgroundColor Black
    }else{
        #The device is joined to the local domain.
        $IS_DJ = $true
        $DomainName = $DSReg | Select-String DomainName 
        $DomainName =($DomainName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Yellow -BackgroundColor Black
    }    

    #Checking if the device connected to AzureAD
    if ($DJ -eq 'YES'){
        #Check if the device is hybrid
        ''
        Write-Host "Testing if the device is Hybrid Azure AD joined..." -ForegroundColor Yellow
        $AADJ = $DSReg | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            #The device is hybrid
            $hostname = hostname
            Write-Host $hostname "device is Hybrid Azure AD joined" -ForegroundColor Green -BackgroundColor Black
            #CheckPRT value
            ''
            Write-Host "Testing Azure AD PRT..." -ForegroundColor Yellow
            $ADPRT = $DSReg | Select-String AzureAdPrt | select-object -First 1
            $ADPRT = ($ADPRT.tostring() -split ":")[1].Trim()
            if ($ADPRT -eq 'YES'){
                #PRT is available
                Write-Host "Test passed: Azure AD PRT is available on this device for the looged on user" -ForegroundColor Green -BackgroundColor Black
                CheckePRT
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }else{
                #PRT not available
                Write-Host "Test failed: Azure AD PRT is not available. Hence SSO is not working and the device may be blocked if you have Conditional Access Policy requires the user to sign-in from trusted device" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support" -ForegroundColor Yellow
                CheckePRT
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }

            exit
        }else{
           $hostname = hostname
           Write-Host $hostname "device is NOT Hybrid Azure AD joined" -ForegroundColor Yellow -BackgroundColor Black
           #Check WPJ
           ''
           Write-Host "Testing if the device is workplace joined..." -ForegroundColor Yellow
           $WPJ = $DSReg | Select-String WorkplaceJoined | Select-Object -First 1
           $WPJ = ($WPJ.tostring() -split ":")[1].trim()
           if ($WPJ -eq 'YES'){
                #Device is WPJ, check the registry
                $hostname = hostname
                Write-Host $hostname "device is workplace joined" -ForegroundColor Green -BackgroundColor Black
                ###check registry
           }else{
                $hostname = hostname
                Write-Host $hostname "device is NOT workplace joined" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD, hence PRT is not valid" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: make sure the device is connected to AAD to get Azure PRT" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit        
           }
        }
        
    }else{
        #Check if the device AADJ
        ''
        Write-Host "Testing if the device is Azure AD Joined..." -ForegroundColor Yellow
        $AADJ = $DSReg | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            #The device AADJ
            $hostname = hostname
            Write-Host $hostname "device is Azure AD joined" -ForegroundColor Green -BackgroundColor Black
            #CheckPRT value
            ''
            Write-Host "Testing Azure AD PRT..." -ForegroundColor Yellow
            $ADPRT = $DSReg | Select-String AzureAdPrt | select-object -First 1
            $ADPRT = ($ADPRT.tostring() -split ":")[1].Trim()
            if ($ADPRT -eq 'YES'){
                #PRT is available
                Write-Host "Test passed: Azure AD PRT is available on this device for the looged on user" -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }else{
                #PRT not available
                Write-Host "Test failed: Azure AD PRT is not available. Hence SSO with O365 services is not working and the device may be blocked if you have Conditional Access Policy requires the user to sign-in from trusted device" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }

           exit
        }else{
           $hostname = hostname
           Write-Host $hostname "device is NOT Azure AD joined" -ForegroundColor Yellow -BackgroundColor Black
           #Check WPJ
           ''
           Write-Host "Testing if the device is workplace joined..." -ForegroundColor Yellow
           $WPJ = $DSReg | Select-String WorkplaceJoined
           $WPJ = ($WPJ.tostring() -split ":")[1].trim()
           if ($WPJ -eq 'YES'){
                #Device is WPJ, check the registry
                $hostname = hostname
                Write-Host $hostname "device is workplace joined" -ForegroundColor Green -BackgroundColor Black
                ###check registry
           }else{
                $hostname = hostname
                Write-Host $hostname "device is NOT workplace joined" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD, hence PRT is not valid" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: make sure the device is connected to AAD to get Azure PRT" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit        
           }
        }
    }
}

Function checkProxy{
# Check Proxy settings
Write-Host "Checking winHTTP proxy settings..." -ForegroundColor Yellow
$ProxyServer="NoProxy"
$winHTTP = netsh winhttp show proxy
$Proxy = $winHTTP | Select-String server
$ProxyServer=$Proxy.ToString().TrimStart("Proxy Server(s) :  ")
$global:Bypass = $winHTTP | Select-String Bypass
$global:Bypass=$global:Bypass.ToString().TrimStart("Bypass List     :  ")

if ($ProxyServer -eq "Direct access (no proxy server)."){
    $ProxyServer="NoProxy"
    Write-Host "Access Type : DIRECT"
}

if ( ($ProxyServer -ne "NoProxy") -and (-not($ProxyServer.StartsWith("http://")))){
    Write-Host "      Access Type : PROXY"
    Write-Host "Proxy Server List :" $ProxyServer
    Write-Host "Proxy Bypass List :" $global:Bypass
    $ProxyServer = "http://" + $ProxyServer
}

$global:login= $global:Bypass.Contains("*.microsoftonline.com") -or $global:Bypass.Contains("login.microsoftonline.com")

$global:device= $global:Bypass.Contains("*.microsoftonline.com") -or $global:Bypass.Contains("*.login.microsoftonline.com") -or $global:Bypass.Contains("device.login.microsoftonline.com")

$global:enterprise= $global:Bypass.Contains("*.windows.net") -or $global:Bypass.Contains("enterpriseregistration.windows.net")

return $ProxyServer
}

Function WPJTS{
    #Check OS version:
    ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
        ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }


#Check dsregcmd status.
$DSReg = dsregcmd /status

#Checking if the device connected to AzureAD
''
Write-Host "Testing if the device is Azure AD Registered..." -ForegroundColor Yellow
$WPJ = $DSReg | Select-String WorkplaceJoined | Select-Object -First 1
$WPJ = ($WPJ.tostring() -split ":")[1].trim()
if ($WPJ -ne "YES"){
    #The device is not connected to AAD:
    ### perform WPJ (all other tests should be here)
    Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD as Azure AD Registered device" -ForegroundColor Red -BackgroundColor Black
        
    #Checking Internet connectivity
    ''
    Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow
    $InternetConn1=$true
    $InternetConn2=$true
    $InternetConn3=$true
    $TestResult = (Test-NetConnection -ComputerName login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green
    }else{
        Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red 
        $InternetConn1=$false
    }

    
    $TestResult = (Test-NetConnection -ComputerName device.login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red 
        $InternetConn2=$false
    }


    $TestResult = (Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red 
        $InternetConn3=$false
    }

    if (($InternetConn1 -eq $true) -or ($InternetConn2 -eq $true) -or ($InternetConn3 -eq $true) ){
        Write-Host "Test passed: user is able to communicate with MS endpoints successfully" -ForegroundColor Green -BackgroundColor Black
    }else{
        Write-Host "Test failed: user is not able to communicate with MS endpoints" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: make sure that the user is able to communicate with the above MS endpoints successfully" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    CheckMSOnline

    #Check DevReg app
    ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green -BackgroundColor Black 
    }else{
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    ''
    ''
    Write-Host "All tests completed successfully. You can start registering your device to Azure AD." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is WPJ join
    $TenantName = $DSReg | Select-String TenantName 
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is connected to Azure AD tenant that has the name of" $TenantName "as Azure AD Register device" -ForegroundColor Green -BackgroundColor Black

}

''
Write-Host "Testing the device status on Azure AD..." -ForegroundColor Yellow

CheckMSOnline

#Check the device status on AAD:
$DID = $DSReg | Select-String WorkplaceDeviceId
$DID = ($DID.ToString() -split ":")[1].Trim()
$AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
#Check if the device exist:
''
Write-Host "Checking if device exist in AAD..." -ForegroundColor Yellow
if ($AADDevice.count -ge 1){
    #The device existing in AAD:
    Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
}else{
    #Device does not exist:
    ###Reregister device to AAD
    Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Disconnect the device from Azure AD form 'settings > Accounts > Access work or school' and then connect it again to AAD." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}

#Check if the device is enabled:
''
Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
if ($AADDevice.Enabled -eq $false){
    ###Enabling device in AAD
    Write-Host "Test failed: the device is not enabled on Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
    Write-Host "Test passed: the device is enabled on Azure AD tenant." -ForegroundColor Green -BackgroundColor Black
}


''
''
Write-Host "The device is connected to AAD as Azure AD Registered device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''
''
    
}#end WPJTS

Function AADJ{
#Check PSAdmin
''
Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow 
if (PSasAdmin){
    # PS running as admin.
    Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green -BackgroundColor Black
}else{
    Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: This test needs to be running with elevated privileges" -ForegroundColor Yellow -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}
#Check OS version:
''
Write-Host "Testing OS version..." -ForegroundColor Yellow
$OSVersoin = ([environment]::OSVersion.Version).major
$OSBuild = ([environment]::OSVersion.Version).Build
if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
    Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

}else{
    # dsregcmd will not work.
    Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}


#Check dsregcmd status.
$DSReg = dsregcmd /status

''
Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
$DJ = $DSReg | Select-String DomainJoin
$DJ = ($DJ.tostring() -split ":")[1].trim()
if ($DJ -ne "YES"){
    $hostname = hostname
    Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow -BackgroundColor Black
}else{
    #The device is joined to the local domain.
    $DomainName = $DSReg | Select-String DomainName 
    $DomainName =($DomainName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Yellow -BackgroundColor Black
    ''
    Write-Host "Recommended action: the selected option runs for AADJ devices. To troubleshoot hybrid devices, rerun the script and select option '3'." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}    

#Checking if the device connected to AzureAD
''
Write-Host "Testing if the device is joined to AzureAD..." -ForegroundColor Yellow
$AADJ = $DSReg | Select-String AzureAdJoined
$AADJ = ($AADJ.tostring() -split ":")[1].trim()
if ($AADJ -ne "YES"){
    #The device is not connected to AAD:
    ### perform AADJ (all other tests should be here)
    Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD" -ForegroundColor Red -BackgroundColor Black

    #Checking if the user is bulitin admin
    ''
    Write-Host "Testing if you signed in user is a Built-in Administrator account..." -ForegroundColor Yellow
    $BAdmin=(Get-LocalUser | where{$_.SID -like "*-500"}).name
    $LUser=$env:username
    if ($BAdmin -eq $LUser){
        Write-Host "Test failed: you signed in using the built-in Administrator account" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: create a different local account before you use Azure Active Directory join to finish the setup." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit        
    }else{
        Write-Host "Test passed: you are not signed in using the built-in Administrator account" -ForegroundColor Green -BackgroundColor Black
    }


    #Checking if the signed in user is a local admin
    ''
    Write-Host "Testing if the signed in user has local admin permissions..." -ForegroundColor Yellow
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        Write-Host "Test passed: the signed in user has local admin permissions" -ForegroundColor Green -BackgroundColor Black
    }else{
        Write-Host "Test failed: the signed in user does NOT have local admin permissions" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: sign in with a user that has local admin permissions before you start joining the device to Azure AD to finish the setup" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit        

    }

        
    #Checking Internet connectivity
    ''
    Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow
    $InternetConn1=$true
    $InternetConn2=$true
    $InternetConn3=$true
    $TestResult = (Test-NetConnection -ComputerName login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green
    }else{
        Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red 
        $InternetConn1=$false
    }

    
    $TestResult = (Test-NetConnection -ComputerName device.login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red 
        $InternetConn2=$false
    }


    $TestResult = (Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red 
        $InternetConn3=$false
    }

    if (($InternetConn1 -eq $true) -or ($InternetConn2 -eq $true) -or ($InternetConn3 -eq $true) ){
        Write-Host "Test passed: user is able to communicate with MS endpoints successfully" -ForegroundColor Green -BackgroundColor Black
    }else{
        Write-Host "Test failed: user is not able to communicate with MS endpoints" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: make sure that the user is able to communicate with the above MS endpoints successfully" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    CheckMSOnline

    #Check DevReg app
    ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green -BackgroundColor Black 
    }else{
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    ''
    ''
    Write-Host "All tests completed successfully. You can start joining your device to Azure AD." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is AAD join
    $TenantName = $DSReg | Select-String TenantName 
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green -BackgroundColor Black

}

''
Write-Host "Testing the device status on Azure AD..." -ForegroundColor Yellow

CheckMSOnline

#Check the device status on AAD:
$DID = $DSReg | Select-String DeviceId
$DID = ($DID.ToString() -split ":")[1].Trim()
$AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
#Check if the device exist:
''
Write-Host "Checking if device exist in AAD..." -ForegroundColor Yellow
if ($AADDevice.count -ge 1){
    #The device existing in AAD:
    Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
}else{
    #Device does not exist:
    ###Rejoin device to AAD
    Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}

#Check if the device is enabled:
''
Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
if ($AADDevice.Enabled -eq $false){
    ###Enabling device in AAD
    Write-Host "Test failed: the device is not enabled on Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
        Write-Host "Test passed: the device is enabled on Azure AD tenant." -ForegroundColor Green -BackgroundColor Black
}


''
''
Write-Host "The device is connected to AAD as Azure AD joined device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''
''    
#end AADJ
}

Function VerifySCP{
  #Check client-side registry setting for SCP
    $SCPClient=$false
    ''
    Write-Host "Testing client-side registry setting for SCP..." -ForegroundColor Yellow
    $Reg=Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
    if (((($Reg.TenantId).Length) -eq 0) -AND ((($Reg.TenantName).Length) -eq 0)) {
       Write-Host "Client-side registry setting for SCP is not configured" -ForegroundColor Yellow -BackgroundColor Black
    }else{
        $SCPClient=$true
        Write-Host "Client-side registry setting for SCP is configured as the following:" -ForegroundColor Green -BackgroundColor Black
        Write-Host "TenantId:" $Reg.TenantId
        $global:TenantName = $Reg.TenantName
        Write-Host "TenantName:" $Reg.TenantName
        #Check client-side SCP info
        ''
        Write-Host "Testing client-side registry configuration..." -ForegroundColor Yellow
        CheckMSOnline
        Write-Host "Checking Tenant ID..." -ForegroundColor Yellow
        $TenantID=((Get-MsolAccountSku).accountobjectid).Guid | Select-Object -first 1
        if ($TenantID -eq $Reg.TenantId){
            Write-Host "Tenant ID is configured correctly" -ForegroundColor Green -BackgroundColor Black
            ''
            Write-Host "Checking Tenant Name..." -ForegroundColor Yellow
            $TNConfigured=$false
            $TName=Get-MsolDomain | where Status -eq Verified
            foreach($TN in $TName.name){
                if ($TN -eq $Reg.TenantName){
                    $TNConfigured =$true
                    $global:DomainAuthType = $TName.Authentication
                    try{
                        $global:MEXURL =  Get-MsolDomainFederationSettings -DomainName $TName.name -ErrorAction Stop
                        $global:MEXURL = $global:MEXURL.MetadataExchangeUri
                    }catch{
                        $global:MEXURLRun=$false
                    }
                }
            }
            if ($TNConfigured -eq $true){
                Write-Host "Tenant Name is configured correctly" -ForegroundColor Green -BackgroundColor Black
            }else{
                Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in registry." -ForegroundColor Yellow
                Write-Host "     Registry path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit
            }

        }else{
            Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in registry." -ForegroundColor Yellow
            Write-Host "     Registry path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }


    }

    #Check connectivity to DC
    $global:DCTestPerformed=$true
    ''
    Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
    $Root = [ADSI]"LDAP://RootDSE"
    $ConfigurationName = $Root.rootDomainNamingContext
    if (($ConfigurationName.length) -eq 0){
        Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure that the device has a line of sight to the Domain controller" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit        
    }else{
        Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green -BackgroundColor Black
    }


    #Check SCP
    if ($SCPClient -eq $false){
        ''
        Write-Host "Checking Service Connection Point (SCP)..." -ForegroundColor Yellow

        $Root = [ADSI]"LDAP://RootDSE"
        $ConfigurationName = $Root.rootDomainNamingContext
        $scp = New-Object System.DirectoryServices.DirectoryEntry;
        $scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
        if ($scp.Keywords -ne $null){
            Write-Host "Service Connection Point (SCP) is configured as following:" -ForegroundColor Green -BackgroundColor Black
            $scp.Keywords
            #check SCP
            ''
            Write-Host "Testing Service Connection Point (SCP) configuration..." -ForegroundColor Yellow
            $TID = $scp.Keywords | Select-String azureADId
            $TID = ($TID.tostring() -split ":")[1].trim()

            $TN = $scp.Keywords | Select-String azureADName
            $TN = ($TN.tostring() -split ":")[1].trim()
            $global:TenantName = $TN
            CheckMSOnline
            Write-Host "Checking Tenant ID..." -ForegroundColor Yellow
            $TenantID=((Get-MsolAccountSku).accountobjectid).Guid | Select-Object -first 1
            if ($TenantID -eq $TID){
                Write-Host "Tenant ID is configured correctly" -ForegroundColor Green -BackgroundColor Black
                ''
                Write-Host "Checking Tenant Name..." -ForegroundColor Yellow
                $TNConfigured=$false
                $TNames=Get-MsolDomain | where Status -eq Verified
                foreach($TName in $TNames){
                    if ($TName.name -eq $TN){
                        $TNConfigured =$true
                        $global:DomainAuthType = $TName.Authentication
                        try{
                            $global:MEXURL =  Get-MsolDomainFederationSettings -DomainName $TName.name -ErrorAction Stop
                            $global:MEXURL = $global:MEXURL.MetadataExchangeUri
                        }catch{
                            $global:MEXURLRun=$false
                        }

                    }
                }
                if ($TNConfigured -eq $true){
                    Write-Host "Tenant Name is configured correctly" -ForegroundColor Green -BackgroundColor Black
                }else{
                    Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red -BackgroundColor Black
                    ''
                    Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in SCP." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit
                }
            }else{
                Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in SCP." -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit
            }

        }else{
            Write-Host "Service Connection Point is not configured in your forest" -ForegroundColor red -BackgroundColor Black
            ''
            Write-Host "Recommended action: make sure to configure SCP in your forest" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }
    }
}

Function LogsCollection{
    ''
    Write-Host "1. Get Auth script from the link https://github.com/CSS-Windows/WindowsDiag/blob/master/ADS/AUTH/Auth.zip"
    ''
    Write-Host "2. Download the ZIP file to client and extract it"
    ''
    Write-Host "3. Rename start-auth.txt and stop-auth.txt to .bat files"
    ''
    Write-Host "4. Create a folder 'MSLogs' and move the start-auth.bat and stop-auth.bat"
    ''
    Write-Host "5. Open up admin command prompt on the win 10 client execute the start-auth.bat"
    ''
    Write-Host "6. Repro the issue"
    ''
    Write-Host "7. Execute stop-auth.bat from admin prompt"
    ''
    Write-Host "8. ZIP and send the logs to Microsoft support for analysis"
    ''
}

Function CheckInternet
{
$statuscode = (Invoke-WebRequest -Uri https://adminwebservice.microsoftonline.com/ProvisioningService.svc -UseBasicParsing).statuscode
if ($statuscode -ne 200){
''
''
Write-Host "Operation aborted. Unable to connect to Azure AD, please check your internet connection." -ForegroundColor red -BackgroundColor Black
exit
}
}

Function CheckMSOnline{
''
Write-Host "Checking MSOnline Module..." -ForegroundColor Yellow
                            
    if (Get-Module -ListAvailable -Name MSOnline) {
        Import-Module MSOnline
        Write-Host "MSOnline Module has imported." -ForegroundColor Green -BackgroundColor Black
        ''
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        
        if ($SavedCreds){
            Connect-MsolService -Credential $UserCreds -ErrorAction SilentlyContinue
        }else{
            Connect-MsolService -ErrorAction SilentlyContinue
        }

        if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
            Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions." -ForegroundColor red -BackgroundColor Black
            exit
        }
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green -BackgroundColor Black
        ''
    } else {
        Write-Host "MSOnline Module is not installed." -ForegroundColor Red -BackgroundColor Black
        Write-Host "Installing MSOnline Module....." -ForegroundColor Yellow
        CheckInternet
        Install-Module MSOnline -force
                                
        if (Get-Module -ListAvailable -Name MSOnline) {                                
        Write-Host "MSOnline Module has installed." -ForegroundColor Green -BackgroundColor Black
        Import-Module MSOnline
        Write-Host "MSOnline Module has imported." -ForegroundColor Green -BackgroundColor Black
        ''
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        Connect-MsolService -ErrorAction SilentlyContinue
        
        if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
            Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions." -ForegroundColor red -BackgroundColor Black
            exit
        }
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        } else {
        ''
        ''
        Write-Host "Operation aborted. MsOnline was not installed." -ForegroundColor red -BackgroundColor Black
        exit
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
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
            
        }


        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode

        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            Write-Host "The certificate subject is not correct." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate subject is correct." -ForegroundColor Green
        }



        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            Write-Host "Certificate Issuer is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate issuer is correct." -ForegroundColor Green
        }


        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            Write-Host "Certificate Algorithm is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm is correct." -ForegroundColor Green
        }


        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            Write-Host "Certificate Algorithm Value is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm Value is correct." -ForegroundColor Green
        }
        

        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            Write-Host "Certificate PrivateKey does not exist." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate PrivateKey is correct." -ForegroundColor Green
        }



    
    }else{
    #Certificate does not exist.
    Write-Host "Device certificate does not exist." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

    }
    

}#End of function

Function CheckUserCert ([String] $DeviceID, [String] $DeviceThumbprint){

    #Search for the certificate:
    if ($localCert = dir Cert:\CurrentUser\My\ | where { $_.Issuer -match "CN=MS-Organization-Access" -and $_.Subject -match "CN="+$DeviceID}){
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
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
            
        }


        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode

        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            Write-Host "The certificate subject is not correct." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate subject is correct." -ForegroundColor Green
        }



        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            Write-Host "Certificate Issuer is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate issuer is correct." -ForegroundColor Green
        }


        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            Write-Host "Certificate Algorithm is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm is correct." -ForegroundColor Green
        }


        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            Write-Host "Certificate Algorithm Value is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm Value is correct." -ForegroundColor Green
        }
        

        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            Write-Host "Certificate PrivateKey does not exist." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate PrivateKey is correct." -ForegroundColor Green
        }



    
    }else{
    #Certificate does not exist.
    Write-Host "Device certificate does not exist." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

    }
    

}#End of function

Function NewFun{

                #The device is hybrid Azure AD join
                $TenantName = $DSReg | Select-String TenantName 
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green
        
                ''
                Write-Host "Checking Key provider..." -ForegroundColor Yellow
                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    Write-Host "The KeyProvider is not configured correctly." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

                }else{
                    Write-Host "Certificate key provider configured correctly." -ForegroundColor Green
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "The device object exists on Azure AD." -ForegroundColor Green
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }

            #Check if the device is registered (not Pending):
            ''
            Write-Host "Checking device PENDING state..." -ForegroundColor Yellow
            [string]$AltSec=$AADDevice.AlternativeSecurityIds
            if (-not ($AltSec.StartsWith("X509:"))){
                Write-Host "Test failed: the device in 'Pending' state on Azure AD." -ForegroundColor Red
                ''
                Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
                Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin. " -ForegroundColor Yellow
                Write-Host "                     - Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and rerun the script." -ForegroundColor Yellow
                Write-Host "                       If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit

            }else{
                    Write-Host "The device is not in PENDING state." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }

        ''
        Write-Host "Checking dual state..." -ForegroundColor Yellow
        $WPJ = $DSReg | Select-String WorkplaceJoined
        $WPJ = ($WPJ.tostring() -split ":")[1].trim()
        if ($WPJ -eq "YES"){
            Write-Host "The device in dual state." -ForegroundColor Red
            ''
            Write-Host "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Azure AD registered state manually before enabling Hybrid Azure AD join by disconnecting the user from Access Work or School Account." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }else{
            #Check if there is atoken inside the path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com
            if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
                Write-Host "The device in dual state." -ForegroundColor Red
                ''
                Write-Host "Recommended action: remove the regostry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit                
            }else{
                Write-Host "The device is not in dual state." -ForegroundColor Green
            }
        }



    ''
    ''
    Write-Host "The device is connected to AAD as hybrid Azure AD joined device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''      
}

Function NewFunAAD{

                #The device is Azure AD joined
                $TenantName = $DSReg | Select-String TenantName 
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green
        
                ''
                Write-Host "Checking Key provider..." -ForegroundColor Yellow
                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    Write-Host "The KeyProvider is not configured correctly." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

                }else{
                    Write-Host "Certificate key provider configured correctly." -ForegroundColor Green
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            ''
            Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Disconnect the device from Azure AD form 'settings > Accounts > Access work or school' and then connect it again to AAD." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit


        }

    ''
    ''
    Write-Host "The device is connected successfully to AAD as Azure AD joined device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''        
}

Function NewFunWPJ{

                #The device is Azure AD joined
                $TenantName = $DSReg | Select-String WorkplaceTenantName 
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is connected to Azure AD tenant that has the name of" $TenantName "as Azure AD Register device" -ForegroundColor Green

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String WorkplaceDeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String WorkplaceThumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckUserCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "The device object exist on Azure AD." -ForegroundColor Green
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Disconnect the device from Azure AD form 'settings > Accounts > Access work or school' and then connect it again to AAD." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit


        }

    ''
    ''
    Write-Host "The device is connected successfully to AAD as Azure AD registered device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''        
}

Function DJ++1{
        #Check OS version:
        ''
        Write-Host "Checking OS version..." -ForegroundColor Yellow
        $OSVersoin = ([environment]::OSVersion.Version).major
        if ($OSVersoin -ge 10){
        Write-Host "Device has current OS version." -ForegroundColor Green
        #Check dsregcmd status.
        $DSReg = dsregcmd /status

        ''
        Write-Host "Checking if the device joined to the local domain..." -ForegroundColor Yellow
        $DJ = $DSReg | Select-String DomainJoin
        $DJ = ($DJ.tostring() -split ":")[1].trim()
        if ($DJ -ne "YES"){
            $hostname = hostname
            Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Red
            ''
            Write-Host "Recommended action: You need to join the device to the local domain in order to perform hybrid Azure AD join." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            #The device is joined to the local domain.
            $DomainName = $DSReg | Select-String DomainName 
            $DomainName =($DomainName.tostring() -split ":")[1].trim()
            $hostname = hostname
            Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Green
    
            #Checking if the device connected to AzureAD
            ''
            Write-Host "Checking if the device is connected to AzureAD..." -ForegroundColor Yellow
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
            #The device is not connected to AAD:
            Write-Host $hostname "device is NOT connected to Azure AD" -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and re-run the script again, if the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

            }else{
                #The device is hybrid Azure AD join
                $TenantName = $DSReg | Select-String TenantName 
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green
        
                ''
                Write-Host "Checking Key provider..." -ForegroundColor Yellow
                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    Write-Host "The KeyProvider is not configured correctly." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

                }else{
                    Write-Host "Certificate key provider configured correctly." -ForegroundColor Green
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "The device object exist on Azure AD." -ForegroundColor Green
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }

            #Check if the device is registered (not Pending):
            ''
            Write-Host "Checking device PENDING state..." -ForegroundColor Yellow
            [string]$AltSec=$AADDevice.AlternativeSecurityIds
            if (-not ($AltSec.StartsWith("X509:"))){
                Write-Host "Test failed: the device in 'Pending' state on Azure AD." -ForegroundColor Red
                ''
                Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
                Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin. " -ForegroundColor Yellow
                Write-Host "                     - Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and rerun the script." -ForegroundColor Yellow
                Write-Host "                       If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit

            }else{
                    Write-Host "The device is not in PENDING state." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit


        }

#
            }

        }

        }else{
            # dsregcmd will not work.
            Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

         
    }

    ''
    ''
    Write-Host "The device is connected to AAD as hybrid Azure AD joined device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
}

Function DJ++{
        #Check OS version:
        ''
        Write-Host "Checking OS version..." -ForegroundColor Yellow
        $OSVersoin = ([environment]::OSVersion.Version).major
        if ($OSVersoin -ge 10){
        Write-Host "Device has current OS version." -ForegroundColor Green
        #Check dsregcmd status.
        $DSReg = dsregcmd /status

        ''
        Write-Host "Checking if the device joined to the local domain..." -ForegroundColor Yellow
        $DJ = $DSReg | Select-String DomainJoin
        $DJ = ($DJ.tostring() -split ":")[1].trim()
        if ($DJ -ne "YES"){
            $hostname = hostname
            Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow
            ''
            Write-Host "Checking if the device joined to Azure AD..." -ForegroundColor Yellow
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
                if ($AADJ -ne "YES"){
                    #The device is not joined to AAD:
                    Write-Host $hostname "device is NOT joined to Azure AD." -ForegroundColor Yellow
                    ''
                    Write-Host "Checking if the device is workplace join..." -ForegroundColor Yellow
                    $WPJ = $DSReg | Select-String WorkplaceJoined
                    $WPJ = ($WPJ.tostring() -split ":")[1].trim()
                        if ($WPJ -ne "YES"){
                            #The device is not WPJ:
                            Write-Host $hostname "device is NOT Workplace Joined." -ForegroundColor Yellow
                            ''
                            Write-Host $hostname "The device is not connected to Azure AD." -BackgroundColor Black -ForegroundColor Red
                            ''
                            ''
                            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                            ''
                            ''
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
            Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Green
    
            #Checking if the device connected to AzureAD
            ''
            Write-Host "Checking if the device is connected to AzureAD..." -ForegroundColor Yellow
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
            #The device is not connected to AAD:
            Write-Host $hostname "device is NOT connected to Azure AD" -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure. To troubleshoot hybrid device registration, re-run the tool and select option #3. If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

            }else{
                NewFun

            }

        }

        }else{
            # dsregcmd will not work.
            Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

         
    }


    
}


Function DJ++TS{
#Check PSAdmin
''
Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow 
if (PSasAdmin){
    # PS running as admin.
    Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green -BackgroundColor Black
}else{
    Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: This test needs to be running with elevated privileges" -ForegroundColor Yellow -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}

#Check OS version:
''
Write-Host "Testing OS version..." -ForegroundColor Yellow
$OSVersoin = ([environment]::OSVersion.Version).major
$OSBuild = ([environment]::OSVersion.Version).Build
if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
    Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

}else{
    # dsregcmd will not work.
    Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}


#Check dsregcmd status.
$DSReg = dsregcmd /status

''
Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
$DJ = $DSReg | Select-String DomainJoin
$DJ = ($DJ.tostring() -split ":")[1].trim()
if ($DJ -ne "YES"){
    $hostname = hostname
    Write-Host $hostname "Test failed: device is NOT joined to the local domain" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: You need to join the device to the local domain in order to perform hybrid Azure AD join." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is joined to the local domain.
    $DomainName = $DSReg | Select-String DomainName 
    $DomainName =($DomainName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Green -BackgroundColor Black
}    

#Checking if the device connected to AzureAD
''
Write-Host "Testing if the device is connected to AzureAD..." -ForegroundColor Yellow
$AADJ = $DSReg | Select-String AzureAdJoined
$AADJ = ($AADJ.tostring() -split ":")[1].trim()
if ($AADJ -ne "YES"){
    #The device is not connected to AAD:
    ### perform DJ++ (all other tests should be here)
    Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD" -ForegroundColor Red -BackgroundColor Black
    #Check Automatic-Device-Join Task
    ''
    Write-Host "Testing Automatic-Device-Join task scheduler..." -ForegroundColor Yellow
    $TaskState=(Get-ScheduledTask -TaskName Automatic-Device-Join).State
    if ($TaskState -ne 'Ready'){
        Write-Host $hostname "Test failed: Automatic-Device-Join task scheduler is not ready" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: please enable 'Automatic-Device-Join' task from 'Task Scheduler Library\Microsoft\Windows\Workplace Join'." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }else{
        Write-Host "Test passed: Automatic-Device-Join task scheduler is ready" -ForegroundColor Green -BackgroundColor Black
    }

    VerifySCP

    #Check connectivity to DC if it has not performed yet
    if ($global:DCTestPerformed=$false){
        ''
        Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
        $Root = [ADSI]"LDAP://RootDSE"
        $ConfigurationName = $Root.rootDomainNamingContext
        if (($ConfigurationName.length) -eq 0){
            Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure that the device has a line of sight to the Domain controller" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit        
        }else{
            Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green -BackgroundColor Black
        }
    }

    #Checking Internet connectivity###
    ''
    Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow
    ###conn
    $ErrorActionPreference= 'silentlycontinue'
    $TestFailed=$false

    $ProxyServer = checkProxy
    ''
    Write-Host "Testing Device Registration Endpoints..." -ForegroundColor Yellow
    if ($ProxyServer -eq "NoProxy"){
        $PSScript = "(Invoke-WebRequest -uri 'login.microsoftonline.com' -UseBasicParsing).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green 
        }else{
            $TestFailed=$true
            Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red 
        }
        $PSScript = "(Invoke-WebRequest -uri 'device.login.microsoftonline.com' -UseBasicParsing).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green 
        }else{
            $TestFailed=$true
            Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red 
        }

        $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/$global:TenantName/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green 
        }else{
            $TestFailed=$true
            Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red 
        }
    }else{
        if ($global:login){
            $PSScript = "(Invoke-WebRequest -uri 'login.microsoftonline.com' -UseBasicParsing).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'login.microsoftonline.com' -UseBasicParsing -Proxy $ProxyServer).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green 
        }else{
            $TestFailed=$true
            Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red 
        }

        if ($global:device){
            $PSScript = "(Invoke-WebRequest -uri 'device.login.microsoftonline.com' -UseBasicParsing).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'device.login.microsoftonline.com' -UseBasicParsing -Proxy $ProxyServer).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green 
        }else{
            $TestFailed=$true
            Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red 
        }

        if ($global:enterprise){
            $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/microsoft.com/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/microsoft.com/discover?api-version=1.7' -UseBasicParsing -Proxy $ProxyServer -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green 
        }else{
            $TestFailed=$true
            Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red 
        }
    }

    # If test failed
    if ($TestFailed){
        ''
        ''
        Write-Host "Test failed: device is not able to communicate with MS endpoints under system account" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended actions: " -ForegroundColor Yellow
        Write-Host "- Make sure that the device is able to communicate with the above MS endpoints successfully under the system account." -ForegroundColor Yellow
        Write-Host "- If the organization requires access to the internet via an outbound proxy, it is recommended to implement Web Proxy Auto-Discovery (WPAD)." -ForegroundColor Yellow
        Write-Host "- If you don't use WPAD, you can configure proxy settings with GPO by deploying WinHTTP Proxy Settings on your computers beginning with Windows 10 1709." -ForegroundColor Yellow
        Write-Host "- If the organization requires access to the internet via an authenticated outbound proxy, make sure that Windows 10 computers can successfully authenticate to the outbound proxy using the machine context." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }

    ###conn

    #Testing if the device synced (with managed domain)
    ''
    Write-Host "Checking domain authenication type..." -ForegroundColor Yellow
    #Check if URL status code is 200
    #check through proxy if exist
    #run under sys account
    $UserRelmURL = "https://login.microsoftonline.com/common/UserRealm/?user=$global:TenantName&api-version=1.0"
    if ($ProxyServer -eq "NoProxy"){
        #$UserRealmJson= Invoke-WebRequest -uri $UserRelmURL -UseBasicParsing
        $PSScript = "Invoke-WebRequest -uri '$UserRelmURL' -UseBasicParsing"
        $UserRealmJson = RunPScript -PSScript $PSScript
     }else{
        #$UserRealmJson= Invoke-WebRequest -uri $UserRelmURL -UseBasicParsing -Proxy $ProxyServer

        $PSScript = "Invoke-WebRequest -uri '$UserRelmURL' -UseBasicParsing -Proxy $ProxyServer"
        $UserRealmJson = RunPScript -PSScript $PSScript
     }
    
    
    $UserRealm = $UserRealmJson.Content | ConvertFrom-Json
    $global:UserRealmMEX = $UserRealm.federation_metadata_url
    $global:FedProtocol = $UserRealm.federation_protocol
    #Check if the domain is Managed
    if ($UserRealm.account_type -eq "Managed"){
        #The domain is Managed
        Write-Host "The configured domain is Managed" -ForegroundColor Green -BackgroundColor Black

        ''
        Write-Host "Checking if the device synced to AAD..." -ForegroundColor Yellow
        $DN=([adsisearcher]"(&(objectCategory=computer)(objectClass=computer)(cn=$env:COMPUTERNAME))").findall().path
        $OGuid = ([ADSI]$DN).ObjectGuid
        $ComputerGUID=(new-object guid(,$OGuid[0])).Guid
        $AADDevice = Get-MsolDevice -DeviceId $ComputerGUID -ErrorAction 'silentlycontinue'
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
        }else{
            #Device does not exist:
            ###Reregister device to AAD
            Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure the device is in the sync scope, and it is successfully exported to Azure AD by AAD Connect." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }

    }else{
    #The domain is federated
    Write-Host "The configured domain is Federated" -ForegroundColor Green -BackgroundColor Black
    #Testing Federation protocol
    ''
    Write-Host "Tesing WSTrust Protocol..." -ForegroundColor Yellow
    if ($global:FedProtocol -ne "WSTrust"){
        #Not WSTrust
        Write-Host "Test failed: WFTrust protocol is not enabled on federation service configuration." -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure that your federation service supports WSTrust protocol, and WSTrust is enabled on AAD federated domain configuration." -ForegroundColor Yellow
        Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }else{
        #WSTrust enabled
        Write-Host "Test passed: WSTrust protocol is enabled on federation service configuration." -ForegroundColor Green -BackgroundColor Black
    }


    #Testing MEX URL
    ''
    Write-Host "Tesing Metadata Exchange URI (MEX) URL..." -ForegroundColor Yellow
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
    if (($ProxyServer -eq "NoProxy") -or ($global:FedProxy)){
        $PSScript = "Invoke-WebRequest -uri $global:UserRealmMEX -UseBasicParsing"
        $WebResponse = RunPScript -PSScript $PSScript
    }else{
        $PSScript = "Invoke-WebRequest -uri $global:UserRealmMEX -UseBasicParsing -Proxy $ProxyServer"
        $WebResponse = RunPScript -PSScript $PSScript
    }

    if ((($WebResponse.Content).count) -eq 0 ){
        #Not accessible
        Write-Host "Test failed: MEX URL is not accessible." -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure the MEX URL $global:UserRealmMEX is accessible." -ForegroundColor Yellow
        Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit

    }else{
        #MEX is accessible
        Write-Host "Test passed: MEX URL '$global:UserRealmMEX' is accessible." -ForegroundColor Green -BackgroundColor Black
        ''
        #count of windowstransport
        Write-Host "Tesing windowstransport endpoints on your federation service..." -ForegroundColor Yellow
        if (([regex]::Matches($WebResponse.Content, "windowstransport" )).count -ge 1){
            #windowstransport is enabled
            Write-Host "Test passed: windowstransport endpoint is enabled on your federation service." -ForegroundColor Green -BackgroundColor Black
        }else{
            Write-Host "Test failed: windowstransport endpoints are disabled on your federation service" -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure that windowstransport endpoints are enabled on your federation service." -ForegroundColor Yellow
            Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit          
        }
        }
}   
        
    #Check DevReg app
    ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green -BackgroundColor Black 
    }else{
        Write-Host "Test failed: Deice Registration Service is disabled on the tenant" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    ''
    ''
    Write-Host "Script completed successfully. You can start hybrid Azure AD registration process." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is hybrid Azure AD join
    $TenantName = $DSReg | Select-String TenantName 
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green -BackgroundColor Black

}

''
Write-Host "Testing the device status on Azure AD..." -ForegroundColor Yellow

CheckMSOnline

#Check the device status on AAD:
$DID = $DSReg | Select-String DeviceId
$DID = ($DID.ToString() -split ":")[1].Trim()
$AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
#Check if the device exist:
''
Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
if ($AADDevice.count -ge 1){
    #The device existing in AAD:
    Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
}else{
    #Device does not exist:
    ###Rejoin device to AAD
    Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}

#Check if the device is enabled:
''
Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
if ($AADDevice.Enabled -eq $false){
    ###Enabling device in AAD
    Write-Host "Test failed: the device is not enabled on Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
        Write-Host "Test passed: the device is enabled on Azure AD tenant." -ForegroundColor Green -BackgroundColor Black
}

#Check if the device is registered (not Pending):
''
Write-Host "Checking device PENDING state..." -ForegroundColor Yellow
[string]$AltSec=$AADDevice.AlternativeSecurityIds
if (-not ($AltSec.StartsWith("X509:"))){
    ###Perform DJ++
    Write-Host "Test failed: the device in 'Pending' state on Azure AD." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
    Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin. " -ForegroundColor Yellow
    Write-Host "                     - Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and re-run the script." -ForegroundColor Yellow
    Write-Host "                       If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
        Write-Host "Test passed: the device is not in PENDING state." -ForegroundColor Green -BackgroundColor Black
}


        ''
        Write-Host "Checking dual state..." -ForegroundColor Yellow
        $WPJ = $DSReg | Select-String WorkplaceJoined
        $WPJ = ($WPJ.tostring() -split ":")[1].trim()
        if ($WPJ -eq "YES"){
            Write-Host "The device in dual state." -ForegroundColor Red
            ''
            Write-Host "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Azure AD registered state manually before enabling Hybrid Azure AD join by disconnecting the user from Access Work or School Account." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }else{
            #Check if there is atoken inside the path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com
            if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
                Write-Host "The device in dual state." -ForegroundColor Red
                ''
                Write-Host "Recommended action: remove the regostry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit                
            }else{
                Write-Host "Test passed: the device is not in dual state." -ForegroundColor Green -BackgroundColor Black
            }
        }



''
''
Write-Host "The device is connected to AAD as hybrid Azure AD joined device, and it is in health state." -ForegroundColor Green -BackgroundColor Black
''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''
''    
}
$global:DomainAuthType=""
$global:MEXURL=""
$global:MEXURLRun=$true
$global:DCTestPerformed=$false
$global:Bypass=""
$global:login=$false
$global:device=$false
$global:enterprise=$false

cls
'========================================================'
Write-Host '        Device Registration Troubleshooter Tool          ' -ForegroundColor Green 
'========================================================'
''
Write-Host "Please provice any feedback, comment or suggestion" -ForegroundColor Yellow
Write-Host
Write-Host "Enter (1) to troubleshoot Azure AD Register" -ForegroundColor Green
''
Write-Host "Enter (2) to troubleshoot Azure AD Join device" -ForegroundColor Green
''
Write-Host "Enter (3) to troubleshoot Hybrid Azure AD Join" -ForegroundColor Green
''
Write-Host "Enter (4) to verify Service Connection Point (SCP)" -ForegroundColor Green
''
Write-Host "Enter (5) to verify the health status of the device" -ForegroundColor Green
''
Write-Host "Enter (6) to Verify Primary Refresh Token (PRT)" -ForegroundColor Green
''
Write-Host "Enter (7) to collect the logs" -ForegroundColor Green
''
Write-Host "Enter (Q) to Quit" -ForegroundColor Green
''

$Num =''
$Num = Read-Host -Prompt "Please make a selection, and press Enter" 

While(($Num -ne '1') -AND ($Num -ne '2') -AND ($Num -ne '3') -AND ($Num -ne '4') -AND ($Num -ne '5') -AND ($Num -ne '6') -AND ($Num -ne '7') -AND ($Num -ne 'Q')){

$Num = Read-Host -Prompt "Invalid input. Please make a correct selection from the above options, and press Enter" 

}

if($Num -eq '1'){
    ''
    Write-Host "Troubleshoot Azure AD Register option has been chosen" -BackgroundColor Black
    ''
    WPJTS
}elseif($Num -eq '2'){
    ''
    Write-Host "Troubleshoot Azure AD Join device option has been chosen" -BackgroundColor Black
    ''
    AADJ
}elseif($Num -eq '3'){
    ''
    Write-Host "Troubleshoot Hybrid Azure AD Join option has been chosen" -BackgroundColor Black
    ''
    DJ++TS
}elseif($Num -eq '4'){
    ''
    Write-Host "Verify Service Connection Point (SCP) has been chosen" -BackgroundColor Black
    ''
    VerifySCP
}elseif($Num -eq '5'){
    ''
    Write-Host "Verify the health status of the device option has been chosen" -BackgroundColor Black
    ''
    DJ++
}elseif($Num -eq '6'){
    ''
    Write-Host "Verify Primary Refresh Token (PRT) option has been chosen" -BackgroundColor Black
    ''
    CheckPRT
}elseif($Num -eq '7'){
    ''
    Write-Host "Collect the logs option has been chosen" -BackgroundColor Black
    ''
    LogsCollection
}