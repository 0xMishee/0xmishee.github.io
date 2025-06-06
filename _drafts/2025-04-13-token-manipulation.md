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

When Windows Vista launched in 2007, Microsoft introduced **User Account Control (UAC)** and **Integrity Levels** as part of a broader effort to improve Windows security. Along with these changes came the concept of the **split token**. This mechanism allows users in the Administrators group to separate their non-elevated tasks from those requiring administrative privileges, such as `SeDebugPrivilege`.

It’s important to clarify that the term **“split token”** doesn’t literally mean a user has two tokens at all times. Instead, it refers to a **filtered token**, which is a type of **restricted token**. Restricted tokens have actually been around since Windows 2000, originally intended for sandboxing scenarios (e.g., isolating browser content). However, they were rarely used in practice.

Prior to Vista, it was common for users, especially administrators, to run with full administrative rights by default. The idea of using a standard user account was rarely enforced or adopted. The introduction of **UAC** in Vista aimed to correct this, forcing **least privilege usage** by default, even for administrative users.

You can see the split token in action below. By utilizing the `logonSessions` tool, we observe my account currently having two active logon sessions. One session has significantly fewer processes, while the other contains a larger number of processes. This demonstrates the elevated usage of my token in action.

![Split Session](/assets/images/token/split-session.png)


# SID, Groups & Privileges
## SID

You may already know that a SID (Security Identifier) is a unique value used to identify a user, but it actually represents more than just users. Technically, a SID is an identifier for a trustee. According to Microsoft, a trustee can be a user account, group, or logon session to which an Access Control Entry (ACE) applies.

These logon sessions don’t necessarily have to belong to a human user. They can also represent Windows services that log on to the local computer using built-in service accounts, such as LocalSystem, LocalService, or NetworkService.

Each of these accounts receives a security token during logon, just like any user would, and this token includes the SID, privileges, and group memberships that define its access rights within the system.

The access control function utlize the TRUSTEE structure, like most things in Windows it all boils down to structures. If you were to supply a name to the function that create an ACE from an TRUSTEE struct, then it would simply allocate a SID buffer and look up the SID by using the provided name.

```c
typedef struct _TRUSTEE_A {
  struct _TRUSTEE_A          *pMultipleTrustee;
  MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
  TRUSTEE_FORM               TrusteeForm;
  TRUSTEE_TYPE               TrusteeType;
  union {
    LPSTR              ptstrName;
    SID                *pSid;
    OBJECTS_AND_SID    *pObjectsAndSid;
    OBJECTS_AND_NAME_A *pObjectsAndName;
  };
  LPCH                       ptstrName;
} TRUSTEE_A, *PTRUSTEE_A, TRUSTEEA, *PTRUSTEEA;
```

### Key Fields in the TRUSTEE Structure

There are a couple of important fields in the `TRUSTEE` structure that need to be understood:

- **TrusteeForm**  
    This field is a pointer that specifies the type of data the trustee represents. Common values include:
    - `TRUSTEE_IS_SID`: Indicates the trustee is identified by a Security Identifier (SID).
    - `TRUSTEE_IS_NAME`: Indicates the trustee is identified by a name.

- **TrusteeType**  
    This enumeration defines the type of trustee being referenced. Possible values include:
    - `TRUSTEE_IS_USER`: The trustee is a user account.
    - `TRUSTEE_IS_GROUP`: The trustee is a group.
    - `TRUSTEE_IS_DOMAIN`: The trustee is a domain.
    - `TRUSTEE_IS_ALIAS`: The trustee is an alias.
    - `TRUSTEE_IS_WELL_KNOWN_GROUP`: The trustee is a well-known group.
    - `TRUSTEE_IS_DELETED`: The trustee has been deleted.
    - `TRUSTEE_IS_INVALID`: The trustee is invalid.
    - `TRUSTEE_IS_COMPUTER`: The trustee is a computer account.

## Groups

Groups are essentially collections of users represented by a single SID. For the Security Reference Monitor, it doesn't matter whether a SID represents an individual user or a group; a SID is treated equally regardless of its type. This means that instead of assigning permissions to individual SIDs, you can group multiple users under a single SID. This approach simplifies the management of Access Control Lists (ACLs), making them easier to handle and maintain.

With that said, there are a few key attributes that the Security Reference Monitor (SRM) considers when evaluating access permissions: **Enabled**, **EnabledByDefault**, and **Mandatory**. 

- **EnabledByDefault**: These are groups or privileges that are automatically enabled when the token is created. They are active unless explicitly disabled.
- **Enabled**: This indicates whether a group is currently active. While you can toggle the enabled state for certain groups, they must first be marked as EnabledByDefault to be activated.
- **Mandatory**: Unlike the other attributes, mandatory groups cannot be toggled on or off. They are always enabled.

These attributes ensure that the SRM can effectively enforce security policies by determining which groups and privileges are applicable during access checks.

![Groups](/assets/images/token/groups.png)

## Privileges

Privileges function as exceptions to the standard access control process, allowing certain actions to bypass traditional access checks entirely. Think of them as special rights that grant the ability to perform tasks without adhering to the usual resource-based access control mechanisms.

Similar to groups, privileges can have different states: **Enabled**, **Disabled**, and **EnabledByDefault**. However, unlike groups, privileges are identified by **Locally Unique Identifiers (LUIDs)**, which we discussed earlier. When a privilege name is provided, the system resolves it to the corresponding LUID, much like how it resolves names to SIDs.

Privileges are not tied to specific resources but instead grant overarching capabilities, making them a powerful tool within the security model.

![EnabledByDefaultPriv](/assets/images/token/EnabledByDefaultPriv.png)

The difference between using a elevated powershell and a none-elevated one.

![Privileges](/assets/images/token/privileges.png)

## Sandboxing

The concept of restricting what a process can and cannot do predates the introduction of UAC and modern access tokens. The first implementation of sandboxing appeared in Windows 2000 through the use of restricted tokens, as mentioned earlier. These tokens were commonly used to enforce either write restrictions or read restrictions. While it was technically possible to apply both restrictions simultaneously, doing so could render the process so limited that it would be unable to perform essential tasks, such as spawning a new process, making it impractical.

Another early approach to sandboxing was employed by Internet Explorer, which utilized integrity levels to create a secure environment. By running the browser at a low integrity level, it effectively operated within a sandbox, isolating it from higher-privileged processes and resources.

A more modern approach involves the use of AppContainers and, by extension, lowbox tokens. These tokens are specifically designed to enforce the principle of least privilege by limiting the actions and interactions of both applications and users. AppContainers combine the identities of the user and the application to create a unique security context for each pairing, ensuring a higher level of isolation and security.

# Where to find them



## PlugX
## QuakLoader

# Add it your malware

