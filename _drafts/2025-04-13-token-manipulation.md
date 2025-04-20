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

Since tokens exist as identifiers within processes to determine the security context they are allowed to operate under, I like to think of the access token embedded in the process as the primary token. It is this primary token that the Security Reference Monitor (SRM) queries to decide what level of access should be granted. The authentication identifier within the primary token uniquely identifies the user’s logon session, and is established during logon by the SRM.

Then comes the issue of needing your process to interact with someone else's files. It's almost as if you need to impersonate that person's identity to gain access to their files. This is where impersonation access tokens come into play. These tokens operate at the thread level, ensuring that the code you execute under someone else's identity is isolated.

There are a few ways to achieve this. You can either grant your threads impersonation access and SetThreadToken access to the thread object, or you can handle direct impersonation access explicitly or implicitly through RPC requests.

```c
void ImpersonationSetThreadToken(){
    BOOL bSTATUS = FALSE;
    HANDLE hToken = NULL; 
    HANDLE hThread = NULL;

    // Assume hToken is obtained via LogonUser or OpenProcessToken.

    // Set impersonation token on current thread
    bSTATUS = SetThreadToken(NULL, hToken);
    if (!bSTATUS) {
        ...
    }

    // Thread will inherit the impersonation context
    hThread = CreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);
    if (!hThread){
        RevertToSelf();
    }

    WaitForSingleObject(hThread, INFINITE);

    ...
}
```

Implicit impersonation through named pipes is a common scenario you may encounter. Services often expose named pipes that clients can connect to. When a client connects to these pipes, the service can leverage the client's impersonation context through the calling thread and process. This allows the service to perform actions on behalf of the client within the client's security context.

```c
void ImpersonationNamedPipe(){
    HANDLE hPipe = NULL;

    hPipe = CreateNamedPipe(
        "\\\\.\\pipe\\MyPipe",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        512, 512, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed: %lu\n", GetLastError());
        return;
    }

    if (ImpersonateNamedPipeClient(hPipe)) {
        HANDLE hToken;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
            printf("[+] Impersonation successful. Got thread token.\n");
            // You could now use this token for querying or duplication
            CloseHandle(hToken);
        } else {
            printf("[-] OpenThreadToken failed: %lu\n", GetLastError());
        }

        // Revert the thread's impersonation context after token operations
        RevertToSelf();
    } else {
        printf("[-] ImpersonateNamedPipeClient failed: %lu\n", GetLastError());
    }

    CloseHandle(hPipe);

}
```

The least common scenario I've encountered involves direct control over impersonation access. This should not be confused with the `THREAD_DIRECT_IMPERSONATION` access right, which is a specific permission. Instead, it refers to the concept of precisely managing what aspects of your security descriptor are being exposed. This level of control allows for fine-tuned adjustments to ensure that only the necessary permissions are granted, minimizing potential security risks; however such fine tuned access is easier managed through the AD, privileges or integrity levels. 

```c
HANDLE hImpersonationToken  = NULL;
HANDLE hThread              = NULL;
DWORD threadId              = 0;

hImpersonationToken = LogonUserAndGetToken(); 

threadId = GetTargetThreadId();

hThread = OpenThread(THREAD_SET_THREAD_TOKEN, FALSE, threadId);

if (hThread == NULL) {
    return;
}

BOOL success = SetThreadToken(&hThread, hImpersonationToken);
```

We can take the concept of impersonation tokens a step further by introducing Security Quality of Service (SQoS). SQoS essentially defines a set of limitations or parameters that control the impersonation level granted to the called process. It allows for fine-grained control over how a process interacts with the security context of another.

```c
typedef struct _SECURITY_QUALITY_OF_SERVICE {
  DWORD                          Length;
  SECURITY_IMPERSONATION_LEVEL   ImpersonationLevel;
  SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
  BOOLEAN                        EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE, *PSECURITY_QUALITY_OF_SERVICE;

```
### Impersonation Levels

From the Microsoft documentation, the impersonation levels are defined as follows:

- **SecurityAnonymous**  
    The server process cannot obtain identification information about the client, and it cannot impersonate the client. This level is defined with no explicit value, defaulting to zero by ANSI C rules.

- **SecurityIdentification**  
    The server process can obtain information about the client, such as security identifiers (SIDs) and privileges, but it cannot impersonate the client. This is useful for servers that export their own objects, such as database products that export tables and views. Using the retrieved client-security information, the server can make access-validation decisions without being able to use other services under the client's security context.

- **SecurityImpersonation**  
    The server process can impersonate the client's security context on its local system. However, it cannot impersonate the client on remote systems.

- **SecurityDelegation**  
    The server process can impersonate the client's security context on remote systems, allowing for a higher level of trust and flexibility in distributed environments.

## Logon Session

As I wrote earlier, an access token serves as an identifier for the privileges and permissions granted to its holder. When a user or entity authenticates with a system, it establishes a session known as a **logon session**. Each logon session is uniquely identified by a **64-bit Locally Unique Identifier (LUID)**. This logon authentication ID acts as a bridge, linking the access token to the corresponding logon session, ensuring that the security context is properly maintained.

When Windows Vista launched in 2007, Microsoft introduced **User Account Control (UAC)** and **Integrity Levels** as part of a broader effort to improve Windows security. Along with these changes came the concept of the **split token**. This mechanism allows users in the Administrators group to separate their non-elevated tasks from those requiring administrative privileges—such as `SeDebugPrivilege`.

It’s important to clarify that the term **“split token”** doesn’t literally mean a user has two tokens at all times. Instead, it refers to a **filtered token**, which is a type of **restricted token**. Restricted tokens have actually been around since Windows 2000, originally intended for sandboxing scenarios (e.g., isolating browser content). However, they were rarely used in practice.

Prior to Vista, it was common for users, especially administrators, to run with full administrative rights by default. The idea of using a standard user account was rarely enforced or adopted. The introduction of **UAC** in Vista aimed to correct this, forcing **least privilege usage** by default, even for administrative users.

You can see the split token in action below. By utilizing the `logonSessions` tool, we observe my account currently having two active logon sessions. One session has significantly fewer processes, while the other contains a larger number of processes. This demonstrates the elevated usage of my token in action.

![Split Session](/assets/images/token/split-session.png)


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