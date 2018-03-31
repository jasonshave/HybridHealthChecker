# Skype for Business Hybrid Health Check Tool

This tool uses PowerShell runspaces along with XAML/WPF controls to provide a UI to various functions which test and validate a customer's hybrid configuration. The tests are designed to validate the best practices for the configuration of a hybrid Skype for Business or Lync Server 2013 environment.

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

3. **GetAccessEdgeConfiguration** - Several tests are performed against the on-premises configuration by getting settings from 'Get-CsAccessEdgeConfiguration'.

