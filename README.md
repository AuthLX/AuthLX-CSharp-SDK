# AuthLX C# Integration Example & SDK

[![C++ Version](https://img.shields.io/badge/.NET%20Framework-4.7.2%2B-blue.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg?style=flat-square)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE.txt)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=flat-square)](#)

A professional C# reference implementation demonstrating integration with **[AuthLX](https://authlx.com)**, a premium authentication, licensing, and security platform. This repository contains a fully self-contained C# SDK and an interactive console menu client featuring thread-safe logging, anti-tampering signatures, and debugger detection.

---

## Table of Contents

- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building the Project](#building-the-project)
- [SDK Architecture & API Guide](#sdk-architecture--api-guide)
  - [Initialization](#initialization)
  - [User Login](#user-login)
  - [User Registration](#user-registration)
- [Structured Logging System](#structured-logging-system)
- [Security Features](#security-features)
  - [HMAC Anti-Tamper Signatures](#hmac-anti-tamper-signatures)
  - [Anti-Debugging & Reverse Engineering](#anti-debugging--reverse-engineering)
  - [Host Whitelisting](#host-whitelisting)
- [License](#license)

---

## Key Features

* **Zero External Dependencies**: Uses a custom, built-in `SimpleJson` engine for lightweight, self-contained compilation with zero NuGet package restores.
* **Compatibility across C# App Types**: Engineered to run safely on Console, Windows Forms (WinForms), WPF, Class Libraries, and background services without crashes.
* **Modern Thread-Safe Logger**: Concurrent logger writing to both console and log files (`logs/sdk.log`). Uses C# caller information attributes for compile-time filename and member extraction.
* **Non-Blocking Network Queries**: Supports integration within asynchronous worker loops.
* **Secure HWID Collection**: Native Win32 user SID extraction and 64-bit Registry `MachineGuid` readers to prevent duplication.

---

## Project Structure

```
├── AuthLX.SDK/                       # SDK Library project (.NET Standard & Core)
│   ├── AuthLX.cs                     # Core C# SDK (API, Logger, Security, SimpleJson)
│   └── AuthLX.SDK.csproj             # SDK library project configuration
│
├── AuthLX CSharp Example/            # Console Demo project (references SDK library)
│   ├── Program.cs                    # Interactive console demo application
│   ├── App.config                    # Standard application configuration
│   └── AuthLX CSharp Example.csproj  # Example app project configuration
│
└── AuthLX CSharp Example.sln         # Visual Studio 2022 Solution
```

---

## Getting Started

### Prerequisites

* **Operating System**: Windows 10 or Windows 11.
* **IDE**: [Visual Studio 2022](https://visualstudio.microsoft.com/).
* **Framework**: .NET Framework 4.7.2 or newer.

### Building the Project

1. Open the solution file `AuthLX CSharp Example.sln` inside Visual Studio 2022.
2. Select **Release** configuration.
3. Build the solution. The compiled binary will be generated in:
   * `<root>/AuthLX CSharp Example/bin/Release/AuthLX CSharp Example.exe`

---

## SDK Architecture & API Guide

The `AuthLX.api` class manages session details, TLS settings, network queries, and local system validation.

### Initialization

Define a static instance of `AuthLX.api` as your global entry point:

```csharp
using AuthLX;

public static api AuthLXApp = new api(
    name: "your_application_name", 
    ownerid: "your_application_owner_id_from_dashboard",
    secret: "your_application_secret_key_from_dashboard",
    version: "1.0"
);
```

### User Login

Authenticate the user using username and password:

```csharp
if (AuthLXApp.login("username", "password")) {
    LogHelper.LogInfo("Successfully authenticated!");
} else {
    LogHelper.LogError("Login failed: " + AuthLXApp.last_message);
}
```

### User Registration

```csharp
if (AuthLXApp.registerAccount("username", "email@domain.com", "password", "LICENSE-KEY")) {
    LogHelper.LogInfo("Successfully registered account!");
}
```

---

## Structured Logging System

The C# SDK includes a concurrent logging system (`AuthLX.Logger`).

### Initialization

To initialize the logger to save to log files and output to the debugger console:

```csharp
// Save to logs/sdk.log, write to console, set level to Debug
Logger.Instance.Init("logs/sdk.log", true, LogLevel.DebugLevel);
```

### Logging Helpers

Write logs cleanly. The compiler automatically populates the file paths and line numbers:

```csharp
LogHelper.LogDebug("Debugging internal state.");
LogHelper.LogInfo("Login processed.");
LogHelper.LogWarn("Rate limit threshold met.");
LogHelper.LogError("Network timeout occurred.");
```

---

## Security Features

### HMAC Anti-Tamper Signatures

When a `client_secret` is configured, requests are signed with an HMAC-SHA256 signature containing a hash of the running assembly, a timestamp, and a cryptographically random nonce.

### Anti-Debugging & Reverse Engineering

Contains Win32 API checks to prevent reverse engineering attempts:

```csharp
Others.AntiDebug();
```

### Host Whitelisting

```csharp
AuthLXApp.set_allowed_hosts(new List<string> { "authlx.com" });
```

---

## License

This project is licensed under the MIT License - see the LICENSE.txt file for details.
