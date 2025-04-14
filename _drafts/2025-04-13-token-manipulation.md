---
title: "Tokens - Welcome to patchwork security"
date: 2024-03-13 15:30:00 +0200  
categories: [SysInternals, Tokens]
tags: [malware, sysinternals, windows]
description: Technical analysis of akira.
comments: false
---


# What, how, why, where?
## The What

An access token is essentially an object that encapsulates a security context, describing the properties and permissions of its holder. Think of it as an identification badge that represents the user's security attributes.

Similar to Active Directory (AD) objects, which include attributes like:
- `objectSID`
- `sAMAccountName`, `userPrincipalName`
- `memberOf`
- `description`, `department`, `title`, etc.

An access token contains:
- User SID (Security Identifier)
- Group SIDs
- Privileges
- Token Type (e.g., Primary or Impersonation)
- Integrity Level
- Default DACL (Discretionary Access Control List)

## The How

The access token is created whenever a user logs in. This can be done through either interactive , remoteinteractive, network, service or batch, they will all create an access token for that user. 

There's a bit of a special case when it comes to users like SYSTEM, Local Service and Network Service. Since they're users and are clearly running processes the question remains on how they're created; which the simply answer is. 


## The Why

The purpose of an access token is to represent an identity for the Security Reference Monitor (SRM) during access checks. The SRM is one of the key components that enables the separation of "what's yours" from "what's mine," while also allowing controlled sharing when necessary. It does this by retrieving the security descriptor of a resource and comparing it to the access token of the requesting process.

## The Where

Processes and threads are generally where they are used, 


# Types
## Primary & Impersonation
## Logon & Session 
# SID, Groups & Privileges
## Sandboxing
# Windows API 

CreateProcessWithTokenW
CreateProcessAsUserA 
ImpersonateLoggedOnUser 
SetThreadToken 
CreateProcessWithLogonW 

# Where to find them
## Cobolt Strike & Sliver & Covenant
## PlugX
## QuakLoader
# Add it your malware
# Detections
## Yara
## Sysmon 
# Further Reading


https://www.nccgroup.com/us/research-blog/demystifying-cobalt-strike-s-make_token-command/

https://github.com/BishopFox/sliver/blob/master/implant/sliver/priv/priv_windows.go#L243
https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Credentials/Tokens.cs#L320