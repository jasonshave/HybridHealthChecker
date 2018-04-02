# Skype for Business Hybrid Health Check Tool

This tool uses PowerShell runspaces along with XAML/WPF controls to provide a UI to various functions which test and validate a customer's hybrid configuration. The tests are designed to validate the best practices for the configuration of a hybrid Skype for Business or Lync Server 2013 environment.

## To Install:

The following pre-requisites are required to run the module:

1. [Skype for Business Online PowerShell Module (Version 7.0.0.0)](https://www.microsoft.com/en-us/download/details.aspx?id=39366)
    - [This requires WMF 5.1 (PowerShell 5.1) as well.](https://www.microsoft.com/en-us/download/details.aspx?id=54616)
2. [Skype for Business Admin tools](https://technet.microsoft.com/en-ca/library/dn933921.aspx) or [Lync Server 2013 Admin tools](https://technet.microsoft.com/en-us/library/gg398665(v=ocs.15).aspx)

Simply type: `Install-Module SkypeForBusinessHybridHealth`

## To Execute:
Simply type: `Invoke-SkypeForBusinessHybridHealthCheck`

Authenticate with an account which has been given Skype for Business administrative rights to complete the tests. 

*NOTE: Accounts enabled for MFA are supported.*

## To Update:
Simply type: `Update-Module SkypeForBusinessHybridHealth`

The following tests are performed:

1. **GetCmsReplicationStatus** - This function checks all Central Management Store (CMS) replicas for any which are not 'up-to-date'. There could be cases where some or all servers show a failed state however this could be normal as replication happens regularly. While a failed replica is not an indication of an issue, there should be some investigation into a possible issue if the tests are run multiple times with the same replica in a failed state. 

2. **GetHostingProviderConfiguration** - This function tests all the required settings returned from the on-premises cmdlet: 'Get-CsHostingProvider'. We validate such settings as:
    - ProxyFqdn (sipfed.online.lync.com)
    - Enabled ($true)
    - SharedAddressSpace ($true)
    - HostOcsUsers ($true)
    - VerificationLevel (UseSourceVerification)
    - IsLocal ($true)
    - AutoDiscoverUrl (tenant specific)

3. **GetAccessEdgeConfiguration** - Several tests are performed against the on-premises configuration by getting settings from 'Get-CsAccessEdgeConfiguration'. The following parameters are evaluated:
    - AllowOutsideUsers ($true)
    - AllowFederatedUsers ($true)
    - PartnerDiscovery ($true)
    - RoutingMethod (UseDnsSrvRouting)

4. **TestFeToEdgePorts** - This function involves querying the Edge servers in topology and locating the pools & servers associated with them. A .NET TCP connect attempt is made using an array of ports from the Front-End servers to each Edge server. Each tested combination is recorded in the results grid within the UI. The following TCP ports are tested:
    - 443
    - 4443
    - 5061
    - 5062
    - 8057
    - 50001
    - 50002
    - 50003

5. **GetSharedSipAddressSpace** - A connection is made from the on-premises computer to Skype for Business Online in an attempt to check the 'SharedSipAddressSpace' parameter. This needs to be set to $true so the test evaluates this.