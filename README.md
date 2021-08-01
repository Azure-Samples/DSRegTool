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
You can run DSRegTool as a normal user, except with option #3 and option #7

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


# Frequently asked questions
## Does this script change anything?
No. It just retrieves data.

## Does this script require any PowerShell module to be installed?
No, the script does not require any PowerShell module.
