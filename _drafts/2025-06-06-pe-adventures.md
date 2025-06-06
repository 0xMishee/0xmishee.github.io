---
title: "PE Adventures"
date: 2023-06-23 15:30:00 +0200  
categories: [SysInternals]
tags: [sysinternals, windows]
description: Digging into what constitutes the PE format.
comments: false
---

# Introduction

Learning what PE files have always been done ad-hoc so thought that I would do it (somewhat) properly. This learning will be in context to getting better at RE and malware analysis.

There’s plenty of good resources to use to learn from, that I will link in the resources section down below. Not everything I learn and read will be written down here because…have you read these docs..!?!

# Relative Virtual Address
Quick note regarding RVA before going into the nitty and gritty of PEs. RVAs are used to avoid hardcoded memory addresses in PEs, they’re simply a offset in memory relative to where the PE was loaded.

“Quick maths”: Target address of a section could be 0x501000 while the loaded address (ImageBase) is located at 0x500000 which puts the RVA at 0x1000.

# PE Structure
## Overview
PE (Portable Executable) are simply a data structure that holds the neccesary information for the OS loader to load the executable into memory and execute it.

PEs can come in several shapes like .dll, .exe, .srv and .cpl.

![PE Sections](/assets/images/pe/pe_headers.webp)

## DOS Header
The DOS header is contains the two required parts that makes a PE file valid. Firstly the MZ (0x5A4D) and secondly the 0x40 value that indicates where the PE header starts.

While parsing for the PE header you would want to get the Imagebase address, so you can access the IMAGE_DOS_HEADER structure since the “e-lfanew;” is the offset of where PE Header starts. Printing this value out would result in a “PE” string.

![DOS_HEADER](/assets/images/pe/image_dos.webp)

## DOS Stub
The DOS Stub are mostly recognized by the “This program cannot be run in DOS mode” string however this isn’t a requirement for the file PE to have. It depends on the compiler what it will say, for example: The Borland compiler will generate a string that says “This program must be run under win32”.

## Rich Header
Might be wondering why Rich Header is here when its clearly not in the table above. That’s because it’s a undocumented header that lays between the DOS Stub and NT Headers. It’s present when the PE is built using Visual Studio toolset.

The relevant information given by the Rich Header are through the 32bit fields dwProdID and dwCount. ProdID consists of two seperate 16bit values that ProdID and Build number. The purpose of ProdID numbers are to identify the behaviour and build makeup of the PE.

You can identify imports, resources, language used (Assembly, C/C++ or Visual Basic) through the ProdID. The amount of ProdIDs can also tell you how large the project file is.

The beginning of the header is marked by the keyword “DanS” which is followed by three null padded ULONGs while the end is marked with the “Rich” keyword followed by a XORed ULONG key which was used to encrypt the header.

## NT Headers
Microsoft documents PE (file), Optional and Data Headers underneath _IMAGE_NT_HEADERS. To access these headers you need to go through the _IMAGE_NT_HEADERS and the Data Header are accessed through the Optional Header Struct.


```c
 struct _IMAGE_NT_HEADERS
{
  ULONG Signature;                               //0x0 "PE"\0\0
  struct _IMAGE_FILE_HEADER Fileheader;          //0x4
  struct _IMAGE_OPTIONAL_HEADER OptionalHeader;  //0x18
};
```

The first 4 Byte ULONG Signature is what we recognize as the PE header.

File header here talks about the file itself. With four primary important ones to take note of.

### Important Fields in `_IMAGE_FILE_HEADER`

| Field Name           | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `Machine`            | Indicates whether the file is 32-bit or 64-bit                              |
| `NumberOfSections`   | Number of sections in the PE file                                           |
| `SizeOfOptionalHeader` | Size of the optional header; used to calculate the offset to the Section Table |
| `Characteristics`    | Flags that describe the characteristics of the file (e.g., DLL, EXE, 32-bit) |


```c
struct _IMAGE_FILE_HEADER
{
  USHORT Machine;               
  USHORT NumberOfSections;       
  ULONG TimeDateStamp;          
  ULONG PointerToSymbolTable;   
  ULONG NumberOfSymbols;        
  USHORT SizeOfOptionalHeader;  
  USHORT Characteristics;       
};
```
The Optional header on the otherhand tells you how the PE file is expected to be loaded into memory. It’s also called optional since some file types don’t have it, like object files; however it’s essential for image files. It also contains the _IMAGE_DATA_DIRECTORY which is just a array 0–15 with our offsets for the different data directories.

Three relevant parts of this header are:

Magic = Identifies the state of the image. Meaning that it identifies the PE as either a 32/64bit image or as a ROM image. It could also have the MAGIC value which makes it identify to either 32/64bit depending on the underlying application.
ImageBase = The prefered address that the PE want to be loaded at. However with todays saftey systems in place like ASLR this is mostly ignored due to that it was “too easy” for malware developers to find the loading addresses of specific files; this can still be achieved through other means.
IMAGE_DATA_DIRECTORY = The 16 long array with offsets for our data directories.
There are 31 members for 32bit and 30 members for 64bit version of this HEADER, so clearly not all of them are represented here. But the above three are the more important ones and you could easily refer to the official documentation (linked below) in specific use cases.

```c
struct _IMAGE_OPTIONAL_HEADER
{
USHORT Magic; 
UCHAR MajorLinkerVersion;
UCHAR MinorLinkerVersion;
ULONG SizeOfCode;
ULONG SizeOfIntiliazedData;
ULONG SizeOfUninitializedData;
ULONG AddressOfEntryPoint;
ULONG BaseOfCode;
ULONG BaseOfData;
ULONG ImageBase;
....
```

```c
_IMAGE_DATA_DIRECTORY DataDirectory;
};
struct _IMAGE_DATA_DIRECTORY {
 ULONG VirtualAddress;
 ULONG Size; 
};
```

Another interesting part of the _IMAGE_DATA DIRECTORY struct is that it contains the IMAGE_BASE_RELOCATION struct, however they also reside in .reloc section. The base relocations list the addresses (locations) where the delta value (Loaded value negative imagebase) needs to be added.

```c
struct _IMAGE_BASE_RELOCATION {
 DWORD VirtualAddress;
 DWORD SizeOfBlock;
};
```

The .reloc is built with a bunch of “blocks” each block starts with the IMAGE_BASE_RELOCATION struct followed by any number of offset field entries.

# Sections
Following the IMAGE_NT_HEADERS are the sections table which is composed of the IMAGE_SECTION_HEADERS struct. The lenght of the section table can be found in the NT headers at FileHeader.NumberOfSections.

Sections usually have the same standard (reserved) names, however they can be named whatever you want. Packed binaries or malware have a tendency to obscure the section names. There’s 24 in total and full list can be found at Microsoft Docs.

### Common PE Section Names

| Section Name | Description                        |
|--------------|------------------------------------|
| `.bss`       | Uninitialized data                 |
| `.data`      | Initialized data                   |
| `.rdata`     | Read-only initialized data         |
| `.reloc`     | Image relocation                   |
| `.text`      | Executable code/data               |
| `.rsrc`      | Resource directory                 |
| `.idata`     | Import tables                      |
| `.edata`     | Export tables                      |


These names are limited by eight characters (sort of) according to the IMAGE_SIZEOF_SHORT_NAME in the IMAGE_SECTION HEADER; however there are ways to go around this by using a offset in the string table instead (but .exe doesn’t use a string table).

The IMAGE_SECTION_HEADER contains some good information to have when analyzing PEs.

### Important Fields in `_IMAGE_SECTION_HEADER`

| Field Name        | Description                                      |
|-------------------|--------------------------------------------------|
| `SizeOfRawData`   | Size of the section on disk                      |
| `Characteristics` | Flags describing the section's properties/content |




| Flag         | Description                           |
|--------------|---------------------------------------|
| `0x00000020` | Contains executable code              |
| `0x00000040` | Contains initialized data             |
| `0x00000080` | Contains uninitialized data           |
| `0x01000000` | Contains extended relocations         |
| `0x10000000` | Section can be shared in memory       |
| `0x20000000` | Section can be executed as code       |
| `0x40000000` | Section can be read                   |
| `0x80000000` | Section can be written to             |


There’s a load more flags, however must of them are reserved for future use or only valid for object files.

```c
 struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
};
```
## Imports Section
The imports structure is somewhat of a mess looking at it, but thankfully corkami had done a great job mapping it out.

![Imports Section](/assets/images/pe/import_struct.webp)

The descriptor is simply a pointer to the table that contains the names of the imports you want to access. Then you have a pointer to the dll that you want to access. In the above example that is kernel32.dll first and then user32.dll.

```c
struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
};
```

### Key Fields in `_IMAGE_IMPORT_DESCRIPTOR`

| Field Name           | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `OriginalFirstThunk` | Pointer to the structure that contains either the function name or ordinal  |
| `Name`               | RVA pointing to the name of the DLL to import from                          |
| `FirstThunk`         | RVA to where the imported function's address will be written at runtime     |


The OrgininalFirstThunk is initself a struct that shows if you want to access the function through the ordinal or through the string. Ordinal is simply a offset within the imports table.

If the ordinal set to a none zero value means that you want to use the ordinal rather than the string value. It’s done this way because of efficiency, so even if you had a string and a ordinal the loader would just choose the ordinal since its slower to user strcmp rather than looking up the index value.

The FirstThink; would during compiling point to the hint/name table in IMAGE_IMPORT_BY_NAME struct which is part of the AddressOfData; in IMAGE_THUNK_DATA but change to the address of the imports once they are loaded.

So to be clear where this Hint/Name are located. “IMAGE_IMPORT_DESCRIPTOR (OriginalFirstThunk) -> IMAGE_THUNK_DATA (AddressOfData) -> IMAGE_IMPORT_BY_NAME (Hint/Name)”

You find the end of the imports table once you find a descriptor with four NULL bytes.

## Exports Section
Export directory doesn’t exist for a lot of files, like .exe files, not because that it can’t exist; but normally such files aren’t used to export functions to other PE files (.dll).

The AddressOfFuntions; doesn’t align with either AddressOfNames or AddressOfNameOrdinals, it uses the Ordinals offset to correspond to the Export Name.

```c
struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;                   // Decides where the offsets starts.
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;          // Number of Entries in the table.
  DWORD AddressOfFunctions;     // RVA of the function for the export. 
  DWORD AddressOfNames;         // Name of the exports, RVA + ImageBase.
  DWORD AddressOfNameOrdinals;  // Index number of the export in the export table.
};
```

Difference when you’re encountering forwarded exports is that the RVA is in the exports section as given by the VirtualAddress and Size fields in the DataDirectory.

# Resources

docs/PE/PE.md at master · corkami/docs (github.com)

Inside Windows: Win32 Portable Executable File Format in Detail | Microsoft Learn

Inside Windows: An In-Depth Look into the Win32 Portable Executable File Format, Part 2 | Microsoft Learn

IMAGE_NT_HEADERS64 (winnt.h) — Win32 apps | Microsoft Learn

IMAGE_FILE_HEADER (winnt.h) — Win32 apps | Microsoft Learn

PE Format — Win32 apps | Microsoft Learn

https://stackoverflow.com/questions/49705700/show-info-about-image-export-directory

