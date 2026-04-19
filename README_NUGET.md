# Haukcode.Mdns

Lightweight mDNS (RFC 6762) and DNS-SD (RFC 6763) for .NET — zero external dependencies, pure managed C#.

## Features

- **Advertise** a service so other devices can discover it via mDNS
- **Browse** for services on the local network
- Multi-adapter multicast — binds to all suitable network interfaces
- RFC-compliant announce sequence, TTL refresh, and goodbye packets
- Cross-platform: Windows, Linux ARM64, macOS

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

## Links

- [GitHub](https://github.com/HakanL/Haukcode.Mdns)
- [RFC 6762 — mDNS](https://datatracker.ietf.org/doc/html/rfc6762)
- [RFC 6763 — DNS-SD](https://datatracker.ietf.org/doc/html/rfc6763)
