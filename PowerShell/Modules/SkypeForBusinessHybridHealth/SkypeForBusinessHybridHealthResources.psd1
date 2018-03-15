###PowerShell Localization File for data
ConvertFrom-StringData @'
RequiredModules = SkypeOnlineConnector,SkypeForBusiness
SkypeOnlineConnector = https://technet.microsoft.com/en-us/library/dn362829(v=ocs.15).aspx
SkypeForBusiness = https://technet.microsoft.com/en-us/library/dn933921.aspx
ModuleLoadErrorMessage = Could not load the required module:
ModuleNotFoundMessage = Could not find this module. Please visit the following URL for more information:
ModuleNoExecuteErrorMessage = The Import-Module function did not execute properly.
SearchingModuleMessage = Searching for module:
ImportModuleMessage = Attempting to import module:
NoSfboConnection = Unable to verify a connection to Skype for Business Online. Please check to ensure you can reach the Internet from your test system and try again.

PSSessionRemovalMessage = Removing existing PSSessions to Skype for Business Online to prevent authentication mismatch.
NewSkypeOnlineSessionMessage = Creating new Skype Online PowerShell session.
ImportingPSSessionMessage = Importing remote PowerShell session.
SFBONoCredsMessage = No credentials specified. Please authenticate to Skype for Business Online.

DomainControllerTestId = 10000
DomainControllerCheckCmd = Get-ADDomainController
DomainControllerMinimumVersion = 6.3
DomainControllerMinimumVersionMessage = Domain Controller Version: 
DomainControllerAuthMessage = Authenticating Domain Controller: 
DomainControllerErrorMessage = The domain controller used in the test was found by querying the logonserver variable in your currently logged on user session. This server's operating system version did not match the expected value.
DomainControllerSuccessMessage = The domain controller operating system version successfuly matched the version queried by this script.
DomainControllerThrowMessage = The command failed to execute

ForestModeTestId = 10001
ForestModeCheckCmd = Get-ADForest
ForestModeMessage = The Active Directory forest mode is set to: 
ForestModeExpectedVersion = Windows2012R2Forest
ForestModeErrorMessage = The Active Directory Forest functional level does not match the expected level.
ForestModeSuccessMessage = The Active Directory Forest functional level matches the expected level.

CMSReplicationTestId = 10002
CMSReplicationSuccessMessage = The Central Management Store (CMS) replication status shows all replication partners up to date.
CMSReplicationErrorMessage = The Central Management Store (CMS) replication status shows one or more replication partners which are out of date.
CMSReplicationExpectedResult = None

AccessEdgeOutsideUsersTestId = 10003
AccessEdgeOutsideUsers = True
AccessEdgeOutsideUsersSuccessMessage = The Access Edge configuration for the AllowOutsideUsers parameter is correctly set.
AccessEdgeOutsideUsersErrorMessage = The Access Edge configuration for the AllowOutsideUsers parameter does not match the expected configuration.

AccessEdgeFederatedUsersTestId = 10004
AccessEdgeFederatedUsers = True
AccessEdgeFederatedUsersSuccessMessage = The Access Edge configuration for the AllowFederatedUsers parameter is correctly set.
AccessEdgeFederatedUsersErrorMessage = The Access Edge configuration for the AllowFederatedUsers parameter does not match the expected configuration.

AccessEdgePartnerDiscoveryTestId = 10005
AccessEdgePartnerDiscovery = True
AccessEdgePartnerDiscoverySuccessMessage = The Access Edge configuration for the EnablePartnerDiscovery parameter is correctly set.
AccessEdgePartnerDiscoveryErrorMessage = The Access Edge configuration for the EnablePartnerDiscovery parameter does not match the expected configuration.

AccessEdgeDnsSrvRoutingTestId = 10006
AccessEdgeDnsSrvRouting = UseDnsSrvRouting
AccessEdgeDnsSrvRoutingSuccessMessage = The Access Edge configuration for the UseDnsSrvRouting parameter is correctly set.
AccessEdgeDnsSrvRoutingErrorMessage = The Access Edge configuration for the UseDnsSrvRouting parameter does not match the expected configuration.

HostingProviderProxyFqdnTestId = 10007
HostingProviderProxyFqdn = sipfed.online.lync.com
HostingProviderProxyFqdnSuccessMessage = The Hosting Provider Proxy FQDN matches the expected value.
HostingProviderProxyFqdnErrorMessage = The Hosting Provider Proxy FQDN does not match the expected value.

HostingProviderEnabledTestId = 10008
HostingProviderEnabled = True
HostingProviderEnabledSuccessMessage = The Hosting Provider is enabled.
HostingProviderEnabledErrorMessage = The Hosting Provider is not enabled.

HostingProviderSharedAddressSpaceTestId = 10009
HostingProviderSharedAddressSpace = True
HostingProviderSharedAddressSpaceSuccessMessage = The EnableAddressSpace parameter of the Hosting Provider is correctly enabled.
HostingProviderSharedAddressSpaceErrorMessage = The EnableAddressSpace parameter of the Hosting Provider is not enabled.

HostingProviderHostOCSUsersTestId = 10010
HostingProviderHostOCSUsers = True
HostingProviderHostOCSUsersSuccessMessage = The Hosting Provider HostOCSUsers parameter matches the expected value.
HostingProviderHostOCSUsersErrorMessage = The Hosting Provider HostOCSUSers parameter does not match the expected value.

HostingProviderVerificationLevelTestId = 10011
HostingProviderVerificationLevel = UseSourceVerification
HostingProviderVerificationLevelSuccessMessage = The Hosting Provider VerificationLevel parameter matches the expected value.
HostingProviderVerificationLevelErrorMessage = The Hosting Provider VerificationLevel parameter does not match the expected value.

HostingProviderIsLocalTestId = 10012
HostingProviderIsLocal = False
HostingProviderIsLocalSuccessMessage = The Hosting Provider IsLocal parameter matches the expected value.
HostingProviderIsLocalErrorMessage = The Hosting Provider IsLocal parameter does not match the expected value.

HostingProviderUrlTestId = 10013
HostingProviderUrlSuccessMessage = The Hosting Provider AutodiscoverUrl parameter matches the expected value.
HostingProviderUrlErrorMessage = The Hosting Provider AutodiscoverUrl parameter does not match the expected value.

HostingProviderTestId = 10014
HostingProviderErrorMesssage = There was no matching Hosting Provider for Skype for Business Online. Please check your configuration and ensure the following steps in this article were performed: https://technet.microsoft.com/en-us/library/jj205126.aspx

TenantSharedSipTestId = 10015
TenantSharedSip = True
TenantSharedSipSuccessMessage = The SharedSipAddressSpace parameter matches the expected value.
TenantSharedSipErrorMessage = The SharedSipAddressSpace parameter does not match the expected value.

TestTcpPortConnectionErrorMessage = There was a problem invoking the command to test TCP port connectivity.
PortTestRemoveDestinationMessage = Removing computer from the source array to prevent the same source being tested as the destination.

FeServerPortTestId = 10016
FeServerPortTestList = 443,4443,5061,5062,8057,50001,50002,50003
FeServerPortTestSuccessMessage = Successfully established TCP connection to server on port:
FeServerPortTestErrorMessage = Unable to establish TCP connection to server on port:
PortTestExpected = Connected

ServicesToPatch = Registrar,MediationServer

FeServiceFriendlyName = Skype for Business Server 2015, Front End Server
FeServiceName = Registrar
FeServerPatchVersionTestId = 10017
FeServerPatchVersion = 6.0.9319.281
FeServerPatchErrorMessage = Failed to match the patch level for:
FeServerPatchSuccessMessage = Successfully matched the patch level for:

MedServiceFriendlyName = Skype for Business Server 2015, Mediation Server
MedServiceName = MediationServer
MedServerPatchVersionTestId = 10018
MedServerPatchVersion = 6.0.9319.272
MedServerPatchErrorMessage = Failed to match the patch level for:
MedServerPatchSuccessMessage = Successfully matched the patch level for:

CompareFederationSettingsTestId = 10019
CompareFederationSettingsOnlineFedError = The global tenant federation setting for Skype for Business Online is disabled.
CompareFederationSettingsSuccessMessage = No issues found with the global federation configuration in the tenant or on-premises.
CompareFederationSettingsAllowFed = True

'@