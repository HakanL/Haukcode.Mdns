# Haukcode.Mdns

Lightweight mDNS (RFC 6762) and DNS-SD (RFC 6763) for .NET — zero external dependencies, pure managed C#.

[![NuGet](https://img.shields.io/nuget/v/Haukcode.Mdns.svg)](https://www.nuget.org/packages/Haukcode.Mdns/)
[![Build](https://github.com/HakanL/Haukcode.Mdns/actions/workflows/main.yml/badge.svg)](https://github.com/HakanL/Haukcode.Mdns/actions/workflows/main.yml)

## Features

- **Advertise** a service so other devices can discover it via mDNS
- **Browse** for services on the local network
- Multi-adapter multicast — binds to all suitable network interfaces
- RFC-compliant announce sequence, TTL refresh, and goodbye packets
- Cross-platform: Windows, Linux ARM64, macOS
- No external dependencies

## Installation

```
dotnet add package Haukcode.Mdns
```

## Advertise a service

```csharp
var profile = new ServiceProfile("My Device", "_http._tcp", port: 80);

using var advertiser = new MdnsAdvertiser(profile);
advertiser.Start();

// Device is now visible on the network
// Dispose to send goodbye packets
```

## Browse for services

```csharp
using var browser = new MdnsBrowser("_http._tcp");

browser.ServiceFound += svc =>
    Console.WriteLine($"Found: {svc.InstanceName} @ {svc.Port}");

browser.ServiceLost += svc =>
    Console.WriteLine($"Lost: {svc.InstanceName}");

browser.Start();
```

## ServiceProfile

`ServiceProfile` describes a service to advertise or summarizes a discovered service:

| Property | Example |
|---|---|
| `InstanceName` | `My Device` |
| `ServiceType` | `_http._tcp` |
| `Port` | `80` |
| `Properties` | `{ "txtvers": "1" }` |
| `FullServiceType` | `_http._tcp.local.` |
| `FullInstanceName` | `My Device._http._tcp.local.` |
| `Hostname` | `My-Device.local.` |

## Announce sequence

The advertiser follows the RFC 6762 announcement sequence:

1. **Probe** — sends a claim packet (SRV + A in the Authority section)
2. **Announce x3** — sends full response (PTR + SRV + TXT + A) with 500 ms / 1 s / 4 s intervals
3. **Steady state** — re-announces at 50%, 90%, and 95% of the PTR TTL (4500 s)
4. **Responds** to incoming PTR queries for the service type
5. **Goodbye** — re-sends with TTL=0 on dispose (x2, 500 ms apart)

## Links

- [RFC 6762 — mDNS](https://datatracker.ietf.org/doc/html/rfc6762)
- [RFC 6763 — DNS-SD](https://datatracker.ietf.org/doc/html/rfc6763)
