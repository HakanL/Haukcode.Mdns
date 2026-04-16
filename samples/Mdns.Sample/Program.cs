using Haukcode.Mdns;

// ---------------------------------------------------------------------------
// Haukcode.Mdns — sample console app
//
// Usage:
//   dotnet run                                    Browse for _apple-midi._udp services
//   dotnet run -- browse <type>                   Browse for a specific service type
//   dotnet run -- advertise <name> <type> <port>  Advertise a service
//   dotnet run -- both <name> <type> <port>       Advertise and browse simultaneously
//
// Examples:
//   dotnet run -- browse _apple-midi._udp
//   dotnet run -- advertise "My Device" _apple-midi._udp 5004
//   dotnet run -- both "My Device" _apple-midi._udp 5004
// ---------------------------------------------------------------------------

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

if (args.Length == 0 || args[0] == "browse")
{
    var serviceType = args.Length >= 2 ? args[1] : "_apple-midi._udp";
    await RunBrowseAsync(serviceType, cts.Token);
}
else if (args[0] == "advertise" && args.Length >= 4)
{
    var name    = args[1];
    var type    = args[2];
    var port    = ushort.Parse(args[3]);
    await RunAdvertiseAsync(name, type, port, cts.Token);
}
else if (args[0] == "both" && args.Length >= 4)
{
    var name    = args[1];
    var type    = args[2];
    var port    = ushort.Parse(args[3]);
    await RunBothAsync(name, type, port, cts.Token);
}
else
{
    Console.WriteLine("""
    Usage:
      dotnet run                                    Browse for _apple-midi._udp services
      dotnet run -- browse <type>                   Browse for a specific service type
      dotnet run -- advertise <name> <type> <port>  Advertise a service
      dotnet run -- both <name> <type> <port>       Advertise and browse simultaneously
    """);
}

// ---------------------------------------------------------------------------
// Browse
// ---------------------------------------------------------------------------

static async Task RunBrowseAsync(string serviceType, CancellationToken ct)
{
    Console.WriteLine($"Browsing for {serviceType} services… (Ctrl+C to stop)\n");

    using var browser = new MdnsBrowser(serviceType);

    browser.ServiceFound += svc =>
    {
        Console.WriteLine($"  [+] {svc.InstanceName}");
        Console.WriteLine($"      Address : {svc.Address}");
        Console.WriteLine($"      Port    : {svc.Port}");
        Console.WriteLine($"      Host    : {svc.Hostname}");
        if (svc.Properties.Count > 0)
        {
            Console.WriteLine("      TXT     :");
            foreach (var kv in svc.Properties)
                Console.WriteLine($"               {kv.Key}={kv.Value}");
        }
        Console.WriteLine();
    };

    browser.ServiceLost += svc =>
        Console.WriteLine($"  [-] {svc.InstanceName} (TTL expired)\n");

    browser.Start();

    try { await Task.Delay(Timeout.Infinite, ct); }
    catch (OperationCanceledException) { }

    Console.WriteLine("\nStopped.");
}

// ---------------------------------------------------------------------------
// Advertise
// ---------------------------------------------------------------------------

static async Task RunAdvertiseAsync(string name, string serviceType, ushort port, CancellationToken ct)
{
    var profile = new ServiceProfile(name, serviceType, port);
    Console.WriteLine($"Advertising '{profile.FullInstanceName}' on port {port}… (Ctrl+C to stop)\n");

    using var advertiser = new MdnsAdvertiser(profile);
    advertiser.Start();

    Console.WriteLine($"  Instance : {profile.FullInstanceName}");
    Console.WriteLine($"  Hostname : {profile.Hostname}");
    Console.WriteLine($"  Port     : {profile.Port}");
    Console.WriteLine();

    try { await Task.Delay(Timeout.Infinite, ct); }
    catch (OperationCanceledException) { }

    Console.WriteLine("\nSending goodbye packets…");
    // Dispose sends the goodbye (handled by using block exit)
}

// ---------------------------------------------------------------------------
// Both: advertise and browse simultaneously
// ---------------------------------------------------------------------------

static async Task RunBothAsync(string name, string serviceType, ushort port, CancellationToken ct)
{
    var profile = new ServiceProfile(name, serviceType, port);
    Console.WriteLine($"Advertising '{profile.FullInstanceName}' and browsing for {serviceType}…");
    Console.WriteLine("(Ctrl+C to stop)\n");

    using var advertiser = new MdnsAdvertiser(profile);
    using var browser    = new MdnsBrowser(serviceType);

    browser.ServiceFound += svc =>
    {
        // Skip our own advertisement
        if (string.Equals(svc.InstanceName, name, StringComparison.OrdinalIgnoreCase))
            return;
        Console.WriteLine($"  [+] {svc.InstanceName}  {svc.Address}:{svc.Port}\n");
    };

    browser.ServiceLost += svc =>
    {
        if (string.Equals(svc.InstanceName, name, StringComparison.OrdinalIgnoreCase))
            return;
        Console.WriteLine($"  [-] {svc.InstanceName} (TTL expired)\n");
    };

    advertiser.Start();
    browser.Start();

    try { await Task.Delay(Timeout.Infinite, ct); }
    catch (OperationCanceledException) { }

    Console.WriteLine("\nSending goodbye packets…");
}
