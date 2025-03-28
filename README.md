# Test-DNSRecord

A simple wrapper for the function Resolve-DNSName to perform DNS queries against a pre-defined list of public DNS Servers and a dynamic list of internal DNS Servers

Copy and Paste the following command to install this package using PowerShellGet More Info

```powershell
Install-Module -Name Test-DNSRecord
```

## Test-DNSRecord Help

```

NAME
    Test-DNSRecord
    
SYNOPSIS
    A simple wrapper for the function Resolve-DNSName to perform DNS queries against specific DNS Servers. The parameters enable you to select from a list of Pubic DNS servers to test DNS resolution for a domain. The DNSProvider switch parameter can also be used to select your internal DNS servers and to test against the domains own Name Servers.
    
    
SYNTAX
    Test-DNSRecord [-recordName] <String[]> [[-Type] <Object>] [[-DNSProvider] <Object>] [<CommonParameters>]
    
    
DESCRIPTION
    A simple wrapper for the function Resolve-DNSName to perform DNS queries against specific DNS Servers. This in no way replaces Resolve-DNSName but provides some simple enhanced queries that do not require you to remember the names or IP Addresses of the Name Servers that you wish to query. This tool does not include all of the functionality of Resolve-DNSName but will speed up everyday DNS queries and diagnostics.
    
    The parameters enable you to select from a list of Pubic DNS servers to test DNS resolution for a domain. The DNSProvider switch parameter can also be used to select you internal DNS servers and to test against the domains own Name Servers.
    
    The internalDNSservers option for the DNSProviders switch performs an AD query to determine the hostname of the Domain Controllers, performs a DNS query against each Domain Controller and displays the results.
    
    The DNSProvider Switch utilises external servers and queries to populate the switch with the relevant internal/external/zone servers to perform the query. Further information can be found in the parameter section.
    
    The list of popular Public DNS Servers was taken from the article - https://www.lifewire.com/free-and-public-dns-servers-2626062 which also provides some useful information regarding DNS and why you might select different public dns servers for your name resolution.
    

PARAMETERS
    -recordName <String[]>
        This is a string and which should container either a fully qualified domain name (FQDN) or an IP address (IPv4 or IPv6)
        
        e.g. example.com or 151.101.0.81
        
        Required?                    true
        Position?                    1
        Default value                
        Accept pipeline input?       true (ByPropertyName)
        Aliases                      
        Accept wildcard characters?  false
        
    -Type <Object>
        You can specify any record type using tab complete. If this parameter is not defined, it defaults to performing an A record DNS query.
        
        The following are contained in a ValidateSet so you can cycle through the record types or manually enter the record type you require.
        
        You can tab complete through a complete list of dns record types or you can enter the record type manually.
        
        Commonly used record types                  Less commonly used record types:
            A (Host address)                            AFSDB (AFS Data Base location)
            AAAA (IPv6 host address)                    ATMA (Asynchronous Transfer Mode address)
            ALIAS (Auto resolved alias)                 CAA (Certification Authority Authorization)
            CNAME (Canonical name for an alias)         CERT (Certificate / CRL)
            MX (Mail eXchange)                          DHCID (DHCP Information)
            NS (Name Server)                            DNAME (Non-Terminal DNS Name Redirection)
            PTR (Pointer)                               HINFO (Host information)
            SOA (Start Of Authority)                    ISDN (ISDN address)
            SRV (location of service)                   LOC (Location information)
            TXT (Descriptive text)                      MB, MG, MINFO, MR (mailbox records)
                                                        NAPTR (Naming Authority Pointer)
        Records types used for DNSSEC                   NSAP (NSAP address)
            DNSKEY (DNSSEC public key)                  RP (Responsible person)
            DS (Delegation Signer)                      RT (Route through)
            NSEC (Next Secure)                          TLSA (Transport Layer Security Authentication)
            NSEC3 (Next Secure v. 3)                    X25 (X.25 PSDN address)
            NSEC3PARAM (NSEC3 Parameters)
            RRSIG (RRset Signature)
        
        Required?                    false
        Position?                    2
        Default value                A
        Accept pipeline input?       true (ByPropertyName)
        Aliases                      
        Accept wildcard characters?  false
        
    -DNSProvider <Object>
        The DNSProvider Switch utilises the external servers and settings detailed below.
        
        The parameter is not mandatory and if not selected will default to using Google's Primary and Secondary public DNS servers.
        
        The switch options are defined as follows:-
            GooglePrimary          = "8.8.8.8"
            GoogleSecondary        = "8.8.4.4"
            Quad9Primary           = "9.9.9.9"
            Quad9Secondary         = "149.112.112.112"
            OpenDNSHomePrimary     = "208.67.222.222"
            OpenDNSHomeSecondary   = "208.67.220.220"
            CloudflarePrimary      = "1.1.1.1"
            CloudflareSecondary    = "1.0.0.1"
            CleanBrowsingPrimary   = "185.228.168.9"
            CleanBrowsingSecondary = "185.228.169.9"
            AlternateDNSPrimary    = "198.101.242.72"
            AlternateDNSSecondary  = "23.253.163.53"
            AdGuardDNSPrimary      = "94.140.14.14"
            AdGuardDNSSecondary    = "94.140.15.15"
            InternalDNSserver      = Performs an AD query to determine the hostname of the Domain Controllers
            DNSZoneNameServers     = Performs a query against the recordname to determine the NameServers for the zone
            AllPublic              = Performs a query using all the Primary and Secondary public servers.
        
        Required?                    false
        Position?                    3
        Default value                
        Accept pipeline input?       true (ByPropertyName)
        Aliases                      
        Accept wildcard characters?  false
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https://go.microsoft.com/fwlink/?LinkID=113216). 
    
INPUTS
    You can pipe objects to these perameters.
    
    - recordName [string - The expected format is a fully qualified domain name or an IP address]
    
    - Type ['A', 'AAAA', 'ALIAS', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'RRSIG', 'AFSDB', 'ATMA', 'CAA', 'CERT', 'DHCID', 'DNAME', 'HINFO', 'ISDN', 'LOC', 'MB', 'MG', 'MINFO', 'MR', 'NAPTR', 'NSAP', 'RP', 'RT', 'TLSA', 'X25']
    
    - DNSProvider ['GooglePrimary', 'GoogleSecondary', 'Quad9Primary', 'Quad9Secondary', 'OpenDNSHomePrimary', 'OpenDNSHomeSecondary', 'CloudflarePrimary', 'CloudflareSecondary', 'CleanBrowsingPrimary', 'CleanBrowsingSecondary', 'AlternateDNSPrimary', 'AlternateDNSSecondary', 'AdGuardDNSPrimary', 'AdGuardDNSSecondary', 'InternalDNSserver', 'DNSZoneNameServers', 'AllPublic']
    
    
OUTPUTS
    System.String. The output returned from Test-DNSRecord is a string
    
    
NOTES
    
    
        Author:     Luke Leigh
        Website:    https://scripts.lukeleigh.com/
        LinkedIn:   https://www.linkedin.com/in/lukeleigh/
        GitHub:     https://github.com/BanterBoy/
        GitHubGist: https://gist.github.com/BanterBoy
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS > Test-DNSRecord
    
    cmdlet Test-DNSRecord at command pipeline position 1
    Supply values for the following parameters:
    (Type !? for Help.)
    recordName[0]: !?
    Please enter DNS record name to be tested. Expectd format is either a fully qualified domain name (FQDN) or an IP address (IPv4 or IPv6) e.g. example.com or
    151.101.0.81)
    recordName[0]: example.com
    recordName[1]:
    
    Name                                           Type   TTL   Section    IPAddress
    ----                                           ----   ---   -------    ---------
    example.com                                    A      19451 Answer     93.184.216.34
    example.com                                    A      19954 Answer     93.184.216.34
    
    This example shows Test-DNSRecord without any options. As recordname is a mandatory field, you are prompted to enter a FQDN or an IP.
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS > Test-DNSRecord -recordName example.com -Type A -DNSProvider GooglePrimary
    
    Name                                           Type   TTL   Section    IPAddress
    ----                                           ----   ---   -------    ---------
    example.com                                    A      20182 Answer     93.184.216.34
    
    This example shows an 'A' record query against Google's Primary Public DNS server.
    
    
    
    
    -------------------------- EXAMPLE 3 --------------------------
    
    PS > Test-DNSRecord -recordName bbc.co.uk -Type CNAME -DNSProvider AllPublic
    
    Name                        Type TTL   Section    PrimaryServer               NameAdministrator           SerialNumber
    ----                        ---- ---   -------    -------------               -----------------           ------------
    bbc.co.uk                   SOA  899   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  899   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  898   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    bbc.co.uk                   SOA  900   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    
    This example shows the results from a CNAME lookup queried against the complete list of Public DNS Servers defined in the DNSProviders parameter.
    
    
    
    
    -------------------------- EXAMPLE 4 --------------------------
    
    PS > Test-DNSRecord -recordName bbc.co.uk -Type CNAME -DNSProvider GooglePrimary -Verbose
    VERBOSE: bbc.co.uk
    VERBOSE: Checking Google Primary...
    
    Name                        Type TTL   Section    PrimaryServer               NameAdministrator           SerialNumber
    ----                        ---- ---   -------    -------------               -----------------           ------------
    bbc.co.uk                   SOA  899   Authority  ns.bbc.co.uk                hostmaster.bbc.co.uk        2021011800
    
    This example displays the output with the verbose option enabled. The function performs the search and details which DNS Provider is being queried.
    
    
    
    
    
RELATED LINKS
    https://github.com/BanterBoy/scripts-blog
    https://www.lifewire.com/free-and-public-dns-servers-2626062
    Resolve-DNSName - https://docs.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname
    Where-Object - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object
    https://github.com/BanterBoy/scripts-blog
    https://www.lifewire.com/free-and-public-dns-servers-2626062
    Resolve-DNSName - https://docs.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname
    Where-Object - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object 


```
