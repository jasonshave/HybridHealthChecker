[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNull()]
    [string] $TenantDomain,

    [Parameter(Mandatory = $false)]
    [Switch] $Edog = $false,

    [Parameter(Mandatory = $false)]
    [string] $ForestFQDN,

    [Parameter(Mandatory = $false)]
    [string] $altForestFQDN = $null,

    [Parameter(Mandatory = $false)]
    [string] $acsFQDN = $null
);

$ErrorActionPreference = "Stop"

if ([System.String]::IsNullOrEmpty($ForestFQDN))
{
    if ($Edog)
    {
        $ForestFQDN = "webdir.tip.lync.com"
    }
    else
    {
        $ForestFQDN = "webdir.online.lync.com"
    }
}

if ([System.String]::IsNullOrEmpty($acsFQDN))
{
    if ($Edog)
    {
        $acsFQDN = "accounts.accesscontrol.windows-ppe.net"
    }
    else
    {
        $acsFQDN = "accounts.accesscontrol.windows.net"
    }
}

# First validate that domain is provisioned on O365 ACS and output Domain and tenant ID
try
{
    $req = [Net.WebRequest]::Create("https://$acsFQDN/metadata/json/1?realm=$TenantDomain")
    Write-Verbose ("Getting ACS json document from {0} ..." -f $req.RequestUri)
    $rsp = $req.GetResponse()
    $str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
    $TenantID = ($str | ConvertFrom-Json).realm
 }
 catch [System.Net.WebException]
 {
     $webEx = ($Error[0].Exception.InnerException) -as [System.Net.WebException]
     if (($webEx -ne $null) -and ($webEx.Status -eq [System.Net.WebExceptionStatus]::ProtocolError))
     {
         throw "Domain $TenantDomain is not registired with ACS/O365"
     }
     throw
 }
 catch
 {
     throw
 }

# Now get response from Lync SfB autodiscover service
$req = [Net.WebRequest]::Create("https://$ForestFQDN/AutoDiscover/AutoDiscoverservice.svc/root?originalDomain=$TenantDomain")
$rsp = $req.GetResponse()
$str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
Write-Verbose $str

$json = ($str | ConvertFrom-Json)
$self = ($json._links.self.href -as [System.URI]).Host
if ([System.String]::IsNullOrEmpty($json._links.redirect.href))
{
    # Since we were not redirected to a different forest, we need to make sure
    # that domain is actually in Lync/SfB online by asking some other forest
    if ([System.String]::IsNullOrEmpty($altForestFQDN))
    {
        switch ($self)
        {
            # Production directors
            "webdir0a.online.lync.com" {$altForestFQDN = "webdir0b.online.lync.com"}
            "webdir0b.online.lync.com" {$altForestFQDN = "webdir0e.online.lync.com"}
            "webdir0e.online.lync.com" {$altForestFQDN = "webdir0f.online.lync.com"}
            "webdir0f.online.lync.com" {$altForestFQDN = "webdir0m.online.lync.com"}
            "webdir0m.online.lync.com" {$altForestFQDN = "webdir0a.online.lync.com"}
            "webdir1a.online.lync.com" {$altForestFQDN = "webdir1b.online.lync.com"}
            "webdir1b.online.lync.com" {$altForestFQDN = "webdir1e.online.lync.com"}
            "webdir1e.online.lync.com" {$altForestFQDN = "webdir2a.online.lync.com"}
            "webdir2a.online.lync.com" {$altForestFQDN = "webdir0a.online.lync.com"}
            "webdirAU1.online.lync.com" {$altForestFQDN = "webdirIN1.online.lync.com"}
            "webdirIN1.online.lync.com" {$altForestFQDN = "webdirJP1.online.lync.com"}
            "webdirJP1.online.lync.com" {$altForestFQDN = "webdirAU1.online.lync.com"}

            # EDOG directors
            "webdir0d.tip.lync.com" {$altForestFQDN = "webdir1d.tip.lync.com"}
            "webdir1d.tip.lync.com" {$altForestFQDN = "webdir0d.tip.lync.com"}

            # Unkown servers
            default 
            {
                if ($self.EndsWith("online.lync.com"))
                {
                    $altForestFQDN = "webdir0m.online.lync.com"
                }
                elseif ($self.EndsWith("tip.lync.com"))
                {
                    $altForestFQDN = "webdir0d.tip.lync.com"
                }
                else
                {
                    throw "Unknown forest FQDN: $self"
                }
            }
        }
    	Write-Verbose "Selected forest $altForestFQDN for second check"
    }
    else
    {
        Write-Verbose "Using forest $altForestFQDN for second check"
    }

    $req = [Net.WebRequest]::Create("https://$altForestFQDN/AutoDiscover/AutoDiscoverservice.svc/root?originalDomain=$TenantDomain")
    $rsp = $req.GetResponse()
    $str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
    Write-Verbose $str

    $json = ($str | ConvertFrom-Json)
    $altSelf = ($json._links.self.href -as [System.URI]).Host
}
if ([System.String]::IsNullOrEmpty($json._links.redirect.href))
{
    throw "Domain $TenantDomain is not in any known SfB/Lync online forest (reported by $self and $altSelf)"
}

$redirect = ($json._links.redirect.href -as [System.URI]).Host
Write-Verbose "Domain $TenantDomain is in $redirect, reported by $self"
$tenantForest = $redirect

$req = [Net.WebRequest]::Create("https://$redirect/WebTicket/WebTicketService.svc/mex")
$req.Headers.Add("X-User-Identity", (-join "user@",$TenantDomain))
$rsp = $req.GetResponse()
$str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
Write-Verbose $str

$namespace = @{
    wsdl="http://schemas.xmlsoap.org/wsdl/"; 
    wsx="http://schemas.xmlsoap.org/ws/2004/09/mex"; 
    wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    wsa10="http://www.w3.org/2005/08/addressing";
    wsp="http://schemas.xmlsoap.org/ws/2004/09/policy";
    wsap="http://schemas.xmlsoap.org/ws/2004/08/addressing/policy";
    msc="http://schemas.microsoft.com/ws/2005/12/wsdl/contract";
    soap12="http://schemas.xmlsoap.org/wsdl/soap12/";
    wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"; 
    wsam="http://www.w3.org/2007/05/addressing/metadata"; 
    xsd="http://www.w3.org/2001/XMLSchema"; 
    tns="http://tempuri.org/"; 
    soap="http://schemas.xmlsoap.org/wsdl/soap/"; 
    wsaw="http://www.w3.org/2006/05/addressing/wsdl"; 
    soapenc="http://schemas.xmlsoap.org/soap/encoding/";
    af="urn:component:Microsoft.Rtc.WebAuthentication.2010"}
$TenantOAuth = (Select-Xml -Namespace $namespace -Content $str -XPath "//af:OAuth/@af:authorizationUri").Node.Value

#Write Output Oject
$properties = @{
    'TenantDomain'=$TenantDomain;
    'TenantID'=$TenantID;
    'TenantForest'=$TenantForest;
    'TenantOAuth'=$TenantOAuth;
}
$object = New-Object -TypeName PSObject -Property $properties
$object | fl *