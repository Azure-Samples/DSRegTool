---
page_type: sample
languages:
- powershell
products:
- azure-active-directory
description: "DSRegTool PowerShell is a comprehensive tool that performs more than 50 different tests that help you to identify and fix the most common device registration issues for all join types (Hybrid Azure AD joined, Azure AD Joined and Azure AD Register)."
urlFragment: "DSRegTool"
---
# Device Registration Troubleshooter Tool
Coming from the fact that it is not so easy to troubleshoot device registration issues and it does take some time, but now, using Device Registration Troubleshooter tool it is not complex anymore :)

DSRegTool PowerShell is a comprehensive tool that performs more than 50 different tests that helps you to identify and fix the most common device registration issues for all join types (Hybrid Azure AD joined, Azure AD Joined and Azure AD Register).

## Script requirements
You can run DSRegTool as a normal user, except with option #3 and option #7 where you need to run DSRegTool with a user who has local admin permissions

## How to run the script
Download and run the `DSRegTool.ps1` script from [this](https://github.com/Azure-Samples/DSRegTool/archive/refs/heads/main.zip) GitHub repo. 

## Why is this script useful?
DSRegTool facilitates troubleshooting device registration issues for different join types

## What are tests DSRegTool perform?
#### 1- Troubleshoot Azure AD Register
- Testing OS version
- Testing if the device is registered to AzureAD by the signed in user
- Testing Device Registration endpoints connectivity
- Testing Device Registration Service
- Testing if the device exists on AAD
- Testing if the device is enabled on AAD 

#### 2- Troubleshoot Azure AD Join device
- Testing OS version
- Testing if the device joined to the local domain
- Testing if the device is joined to AzureAD
- Testing if you signed in user is a Built-in Administrator account
- Testing if the signed in user has local admin permissions
- Testing Device Registration endpoints connectivity
- Testing Device Registration Service
- Testing if the device exists on AAD.
- Testing if the device is enabled on AAD 

#### 3- Troubleshoot Hybrid Azure AD Join
- Testing OS version
- Testing if the device joined to the local domain
- Testing if the device is joined to AzureAD
- Testing Automatic-Device-Join task scheduler
- Testing Domain Controller connectivity
- Testing Service Connection Point (SCP) configuration for both client and domain sides
- Testing Device Registration endpoints connectivity under system context:
    - Testing connectivity over winHTTP proxy (considering if domain is bypassed)
    - Testing connectivity over winInet proxy (considering if domain is bypassed)
- Testing the following with Federated domain:
    - Testing MEX endpoint (for Federated domains)
    - Testing windowstransport endpoints (for Federated domains)
    - If federated join flow failed, checking sync join flow
    - Testing OS version if it supports fallback to sync join
    - Testing fallback to sync join configuration enablement
- Testing the following with Managed domain / Sync join flow:
    - Testing if the device synced successfully to AAD (for Managed domains)
    - Testing userCertificate attribute under AD computer object
    - Testing self-signed certificate validity
    - Testing if the device synced to Azure AD
- Testing Device Registration Service
- Test if the device exists on AAD.
- Test if the device enabled on AAD.
- Test if the device is not pending on AAD.
- Testing if device is stale

#### 4- Verify Service Connection Point (SCP)
- Testing client-side registry setting
- Testing client-side registry configuration (tenantID, DomainName)
- Testing Domain Controller connectivity
- Testing Service Connection Point (SCP) on configuration partition
- Testing Service Connection Point (SCP) configuration 

#### 5- Verify the health status of the device
- Checks OS version
- Checks if the device joined to the local domain
- Checks if the device is joined to AzureAD
- Checks if the device hybrid, Azure AD Join or Azure AD Register
- Checks the device certificate configuration.
- Checks if the device exists on AAD.
- Checks if the device enabled on AAD.
- Checks if the device is not pending on AAD
- Shows the health status for the device
- Provides recommendations to fix unhealthy devices 

#### 6- Verify Primary Refresh Token (PRT)
- Checks OS version
- Checks if the device joined to the local domain
- Testing if the device is Hybrid Azure AD joined
- Testing if the device is Azure AD Joined
- Testing Azure AD PRT (DJ++ or ADDJ)
- Testing Enterprise PRT (DJ++)
- Testing if the device is workplace joined
- Testing the registry configuration (WPJ) 

#### 7- Collect the logs
- If DSRegTool is running with elevated privileges, start log collection. Otherwise, tool shows action plan to collect the logs using Feedback hub.
    
## User experience
![Alt text](/media/DSRegTool.png "DSRegTool")

## Log collection Output File Reference:
| File Name  | Description |
| ------------- | ------------- |
| dsregcmd-status.txt | Contains dsregcmd /status output |
| dsregcmd-debug.txt | Contains dsregcmd /debug output under system context |
| DeviceInfo.txt | Contains the following machine's information: OS version, Device Name, Object GUID, Distinguished Name and UserCertificate |
| hosts.txt | Copy of machine's hosts file |
| ipconfig-all.txt | Contains machine's IP address configuration |
| Winver.txt | Contains Windows OS version |
| IdentityStore.txt | Contains HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore registry value |
| WPJ-info.txt | Contains HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD registry value |
| CloudDomainJoin.txt | Contains HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin registry value |
| WorkplaceJoin-windows.txt | Contains HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin registry value |
| Winlogon-current-control-set.txt | Contains HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon registry value |
| WorkplaceJoin-control.txt | Contains HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WorkplaceJoin registry value |
| Lsa.txt | Contains HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa registry value |
| winInet-user.txt | Contains winHTTP configuration under logged on user context |
| winInet-user-regkey.txt | Contains winInet registry value under logged on user context |
| winHTTP.txt | Contains winHTTP configuration under system context |
| winInet-system-regkey.txt | Contains winInet registry value under system context |
| winInet-system.txt | Contains winInet configuration under system context |
| TestDeviceRegConnectivity-user.txt | Contains the result of testing Device Registration endpoints connectivity under system context |
| TestDeviceRegConnectivity-system.txt | Contains the result of testing Device Registration endpoints connectivity under system context |
| Task-Scheduler.txt | Contains Task scheduler configuration |
| tasklist.txt | Contains running tasks |
| set.txt | Contains system environment values |
| services-running.txt | Contains running services |
| services-config.txt | Contains sc config |
| SCP-config-partition.txt | Contains SCP from domain configuration partition |
| SCP-client-side.txt | Contains SCP client-side registry value |
| Schannel.txt | Contains Schannel registry value |
| GPResult.htm | Contains Group Policy Result |
| Patches.htm | Contains installed windows updates |
| netstat-nao.txt | Contains of established network connections |
| route-print.txt | Contains routing table |
| Netsetup.log | Contains Netsetup debug logs |
| netlogon.log | Contains Netlogon debug logs |
| Netlogon.txt | Contains Netlogon registry value |
| Microsoft-Windows-AAD-Operational.evtx | CloudAP plugin and AAD broker plugin operational logs |
| Microsoft-Windows-AAD-Analytic.evtx | CloudAP plugin and AAD broker diagnostic logs |
| Microsoft-Windows-User Device Registration-Admin.evtx | Device Registration administrative logs |
| Microsoft-Windows-User Device Registration-Debug.evtx | Device Registration diagnostic logs |
| Microsoft-Windows-Biometrics-Operational.evtx | Biometrics operational logs|
| Microsoft-Windows-HelloForBusiness-Operational.evtx | Windows Hello for Business logs |
| Microsoft-Windows-LiveId-Operational.evtx | Live ID operational logs |
| Microsoft-Windows-Kerberos-Operational.evtx | Kerberos operational logs |
| Microsoft-Windows-Shell-Core-Operational.evtx | Shell core operational logs |
| Microsoft-Windows-WebAuthN-Operational.evtx | WebAuthN operational logs including FIDO key logs  |
| Microsoft-Windows-WebAuth-Operational.evtx | WebAuth operational logs |
| Microsoft-Windows-WMI-Activity-Operational.evtx | WMI activity operational logs |
| Microsoft-Windows-Authentication-AuthenticationPolicyFailures-DomainController.evtx | Authentication Policy Failur logs |
| Microsoft-Windows-Authentication-ProtectedUser-Client.evtx | Protected user failure client logs |
| Microsoft-Windows-Authentication-ProtectedUserFailures-DomainController.evtx | Protected user failure authentication logs |
| Microsoft-Windows-Authentication-ProtectedUserSuccesses-DomainController.evtx | Protected user successes authentication logs |
| Microsoft-Windows-CAPI2-Operational.evtx | Certificate operational logs |
| Microsoft-Windows-CertPoleEng-Operational.evtx | CertPoleEng operational logs |
| Microsoft-Windows-Crypto-DPAPI-Operational.evtx | Crypto DPAPI operational logs |
| Microsoft-Windows-GroupPolicy-Operational.evtx | Group policy operational logs |
| Microsoft-Windows-IdCtrls-Operational.evtx | IdCtrls operational logs |
| Microsoft-Windows-User Control Panel-Operational.evtx | Control panel operational logs |
| System.evtx | Machine system event logs |
| Application.evtx | Machine application event logs |
| LSA.etl | contains LSA debug traces in binary format |
| Netmon.etl | contains network trace |
| WebAuth.etl | contains WebAuth debug traces in binary format |
| Kerberos.etl | contains Kerberos debug traces in binary format |
| Ntlm_CredSSP.etl | contains Ntlm_CredSSP debug traces in binary format |
| AADExtention\ </br> Azure.ActiveDirectory.AADLoginForWindows | AADExtention logs |
| AADExtention\ </br> AzuerVMInfo.txt | Contains Azure VM information |
| AADExtention\ </br> AzureVMTenantID.txt | Contains Tenant ID that is associated with the Azure Subscription |
| AADExtention\ </br> AzureVMAccessToken.txt | Contains Azure VM Access Token |
| AADExtention\ </br> pas.windows.net.txt | contains connectivity result to pas.windows.net |
| AADExtention\ </br> login.microsoftonline.com.txt | contains connectivity result to login.microsoftonline.com |
| AADExtention\ </br> device.login.microsoftonline.com.txt | contains connectivity result to device.login.microsoftonline.com |
| AADExtention\ </br> enterpriseregistration.windows.net.txt | contains connectivity result to enterpriseregistration.windows.net |
| Log.log | Shows log collection verbose logs |
| DSRegTool.log | Copy of DSRegTool log file |

# Frequently asked questions
## Does this script change anything?
No. It just retrieves data.

## Does this script require any PowerShell module to be installed?
No, the script does not require any PowerShell module.
