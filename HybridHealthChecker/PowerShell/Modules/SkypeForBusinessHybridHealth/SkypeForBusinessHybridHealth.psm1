function Get-SkypeForBusinessHybridHealth{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="Please enter your Office 365 domain:",Position=1,ParameterSetName="OnPrem")]$TenantDomain,
        [Parameter(Mandatory=$false,ParameterSetName="OnPrem")][PSCredential]$SkypeOnlineCredentials,
        [Parameter(Mandatory=$false,ParameterSetName="OnPrem")][switch]$OverrideAdminDomain,
        [Parameter(Mandatory=$false,ParameterSetName="Edge")][switch]$TestEdgeServer
    )

    begin{
        #import resources file
        try{
            Import-LocalizedData -BindingVariable Resources -FileName "SkypeForBusinessHybridHealthResources.psd1" -ErrorAction SilentlyContinue -ErrorVariable errorMessage
        }catch{
            throw;
        }

        if (!$TestEdgeServer){
            #validate required modules
            [array]$requiredModules = ($resources.RequiredModules).split(",")
            $requiredModules | ModuleValidation

            #get objects to perform tests
            $authDC = GetAuthDc
            $tenantInfo = GetTenantInfo -TenantDomain $TenantDomain
        }

        #start SFBO connection
        InvokeSkypeOnlineConnection
    }
    process{
        #tests
        if (!$TestEdgeServer){
            GetDomainControllerData
            GetForestData
            GetCmsReplicationStatus
            GetAccessEdgeConfiguration
            GetHostingProviderConfiguration
            GetTenantFederationConfiguration
            CompareFederationBetweenOnlineOnPrem
            TestFrontEndServers
            TestServerPatchVersion
        }

    }
    end{
        Get-PSSession | Remove-PSSession
    }
}

function Invoke-SkypeForBusinessHybridHealthCheck {
    [CmdletBinding()]
 
    Param(
        #[Parameter()]$Global:XamlPath = Get-Content -Path (Split-Path (Get-Module SkypeForBusinessHybridHealth).Path) + "\MainWindow.xaml"
    )
 
    begin {
        #set constants
        $2013Tools = "https://technet.microsoft.com/en-us/library/gg398665(v=ocs.15).aspx"
        $2015Tools = "https://technet.microsoft.com/en-ca/library/dn933921.aspx"
        $SFBOTools = "https://www.microsoft.com/en-us/download/details.aspx?id=39366"

        $XamlPath = "C:\users\jason.shave\source\repos\HybridHealthChecker\HybridHealthChecker\PowerShell\Modules\SkypeForBusinessHybridHealth\MainWindow.xaml"
        $formMain = XamlConversion -xmlWpfPath $XamlPath
    }

    process {

        $SFBMainForm.Add_Loaded(
            {
                FormFirstRun
                FormCheckModules($SFBcomboVersion.SelectedValue)
            }
        )

        $SFBMainForm.Add_Closed(
            {
 
            }
        )

        $SFBcomboVersion.Add_SelectionChanged(
            {
                FormCheckModules($SFBcomboVersion.SelectedValue)
            }
        )

        $SFBbtnAdminInstalled.Add_Click(
            {
                switch ($SFBcomboVersion.SelectedValue) {
                    "Skype for Business Server 2015" { Start-Process $2015Tools }
                    "Lync Server 2013" { Start-Process $2013Tools }
                }
            }
        )

        $SFBbtnSFBOAdminInstalled.Add_Click(
            {
                Start-Process $SFBOTools]
            }
        )

        $SFBnavFeedback.Add_Click(
            {
                Start-Process $SFBnavFeedback.NavigateUri
            }
        )

        $SFBnavGitHub.Add_Click(
            {
                Start-Process $SFBnavGitHub.NavigateUri
            }
        )
        
        $SFBbtnStartTests.Add_Click(
            {
                #clear previous test results
                $SFBgridResults.Items.Clear()
                $SFBgridResults.Visibility = "Visible"
                $SFBtabMain.SelectedIndex = 1

                
    
                    $authDC = ($env:LOGONSERVER).Replace("\\","") + "." + $env:USERDNSDOMAIN
                    $forestData = Invoke-Command -ComputerName $authDC -ScriptBlock {Get-ADForest} -ErrorAction SilentlyContinue -ErrorVariable forestErr
                    $forestMode = $forestData.ForestMode

                    [array]$outputResult = [PSCustomObject][ordered]@{
                        TestId = '0001'
                        TestName = 'GetForestData'
                        TestedResult = $(if($SFBcomboForest.SelectedValue -ne $forestMode){"FAIL"}else{"PASS"})
                        ExpectedValue = $SFBcomboForest.SelectedValue
                        TestedValue = $forestMode
                        TestMessage = $null
                        SourceComputerName = ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)
                        DestinationComputerName = $authDC
                        TestDate = $(Get-Date)
                    }

                #Start-Job -ScriptBlock $foo -Name GetForestData | Wait-Job | Receive-Job

                $SFBgridResults.AddChild($outputResult)
                
                
                #wrap it up
                $SFBtxtStatus1.Text = "Finished"
                $SFBbarStatus.Visibility = "Hidden"
            }
        )

        $formMain.ShowDialog()
        
    }

    end {

    }

}

# INTERNAL FUNCTIONS #
function XamlConversion {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)][string]$xmlWpfPath
    )

    begin {
        Add-Type -AssemblyName PresentationFramework
        $Global:xmlWPF = Get-Content -Path $xmlWpfPath
    }

    process {
        #consume XML and strip unwanted tags
        [xml]$xAML = $xmlWPF -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'
        $xmlReader = (New-Object System.Xml.XmlNodeReader $xAML)

        try {
            $formMain = [Windows.Markup.XamlReader]::Load( $xmlReader )
        } catch {
            Write-Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged properties (PowerShell cannot process them)"
            throw;
        }
        
        $xAML.SelectNodes("//*[@Name]") | ForEach-Object {
            Set-Variable -Name "SFB$($_.Name)" -Value $formMain.FindName($_.Name) -Scope Global -Force -ErrorAction Stop
        }

    }

    end {
        return $formMain
    }
}

function FormFirstRun {
    $SFBcomboVersion.SelectedIndex = 0
    $SFBcomboVersion.ItemsSource = @("Skype for Business Server 2015","Lync Server 2013")

    $SFBcomboForest.SelectedIndex = 0
    $SFBcomboForest.ItemsSource = @("Windows2016Forest","Windows2012R2Forest","Windows2012Forest","Windows2008R2Forest","Windows2008Forest")

    #set the version attribute on the help tab
    $modVer = (Get-Module SkypeForBusinessHybridHealth).Version
    if (!($modVer)) {
        $SFBtxtVersion.Text = "Unable to determine version"
    } else {
        #$SFBtxtVersion.Text = $modVer.Major + "." + $modVer.Minor + "." + $modVer.Build + "." + $modVer.Revision
    }
    
}

function FormCheckModules ($ModuleName) {
    #detect modules for on-prem pieces
    switch ($ModuleName) {
        "Skype for Business Server 2015" { 
            $ModuleName = "SkypeForBusiness"
            $SFBtxtOnPremModuleName.Text = "Skype for Business Server 2015 PowerShell Module"
        }
        "Lync Server 2013" {
            $ModuleName = "Lync"
            $SFBtxtOnPremModuleName.Text = "Lync Server 2013 PowerShell Module"
        }
        Default {
            $ModuleName = "Skype for Business Server 2015"
        }
    }

    if (!(Get-Module $ModuleName -ListAvailable)) {
        $SFBbtnAdminInstalled.IsEnabled = $true
        $SFBbtnAdminInstalled.Content = "More Info"
    } else {
        $SFBbtnAdminInstalled.IsEnabled = $false
        $SFBbtnAdminInstalled.Content = "Installed"
    }

    #detect if SFBO module is available
    if (!(Get-Module SkypeOnlineConnector -ListAvailable)) {
        $SFBbtnSFBOAdminInstalled.IsEnabled = $true
        $SFBbtnSFBOAdminInstalled.Content = "More Info"
    }

    if ($SFBbtnAdminInstalled -and $SFBbtnSFBOAdminInstalled) {
        $SFBbtnStartTests.IsEnabled = $true
    }

}

$someFunctions = {

    function GetForestData{
    
        $authDC = ($env:LOGONSERVER).Replace("\\","") + "." + $env:USERDNSDOMAIN
        $forestData = Invoke-Command -ComputerName $authDC -ScriptBlock {Get-ADForest} -ErrorAction SilentlyContinue -ErrorVariable forestErr
        $forestMode = $forestData.ForestMode
    
        [array]$outputResult = [PSCustomObject][ordered]@{
            TestId = '0001'
            TestName = 'GetForestData'
            TestedResult = $(if($SFBcomboForest.SelectedValue -ne $forestMode){"FAIL"}else{"PASS"})
            ExpectedValue = $SFBcomboForest.SelectedValue
            TestedValue = $forestMode
            TestMessage = $null
            SourceComputerName = ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)
            DestinationComputerName = $authDC
            TestDate = $(Get-Date)
        }
        
        $SFBgridResults.AddChild($outputResult)
    }
}



function InstallAdminTools ($Version) {
    #verify all tools are available
    $binPath = (get-module SkypeForBusinessHybridHealth).modulebase + "\bin"
    switch ($Version) {
        "Lync Server 2013" {
            $2013Tools = $binPath + "\2013\"

            $SFBtxtStatus1.Text = "Installing Visual C++ Redistributable..."
            $vcInstall = Start-Process -FilePath ($2013Tools + "vcredist_x64.exe") -ArgumentList "/install /passive /norestart" -Wait
            $SFBbarStatus.Value = "20"

            $SFBtxtStatus1.Text = "Installing SQL CLR Types..."
            $clrInstall = Start-Process -FilePath ($2013Tools + "SQLSysClrTypes.msi") -ArgumentList "/qr" -Wait
            $SFBbarStatus.Value = "40"

            $SFBtxtStatus1.Text = "Installing SQL Shared Management Objects..."
            $smoInstall = Start-Process -FilePath ($2013Tools + "SharedManagementObjects.msi") -ArgumentList "/qr" -Wait
            $SFBbarStatus.Value = "60"
            
            $SFBtxtStatus1.Text = "Installing OCSCORE.msi..."
            $ocsInstall = Start-Process -FilePath ($2013Tools + "ocscore.msi") -ArgumentList "/qr" -Wait
            $SFBbarStatus.Value = "80"
            
            $SFBtxtStatus1.Text = "Installing Visual C++ Redistributable..."
            $adminInstall = Start-Process -FilePath ($2013Tools + "admintools.msi") -ArgumentList "/qr" -Wait
            $SFBbarStatus.Value = "100"
            
          }
        "Skype for Business Server 2015" {
            $2015Tools = $binPath + "\2015\"
        }
    }
}

function ModuleValidation{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)][array]$ModuleName
    )

    begin {}
    process {
        $foundModule = $true
        if (!(Get-Module $ModuleName)){
            #module is not loaded
            Write-Verbose -Message $($resources.SearchingModuleMessage + $ModuleName)
            $foundModule = Get-Module -ListAvailable | Where-Object Name -eq $ModuleName
            if ($foundModule){
                #module was found on the system
                Write-Verbose -Message $resources.ImportModuleMessage
                try{
                    Import-Module $ModuleName -ErrorAction SilentlyContinue -ErrorVariable moduleError
                }catch{
                    #import-module did not execute
                    throw $($ModuleName + ": " + ($resources.ModuleNoExecuteErrorMessage) + " " + $resources.$($ModuleName))
                }
                if ($moduleError){
                    #import-module executed but returned an error
                    throw $($ModuleName + ": " + ($resources.ModuleLoadErrorMessage) + " " + $resources.$($ModuleName))
                }
            }else{
                #module was not found and is not loaded
                 throw $($ModuleName + ": " + ($resources.ModuleNotFoundMessage) + " " +  $resources.$($ModuleName))
            }
        }
    }
    end {}
}

function GetCmsReplicationStatus{
    [cmdletbinding()]
    Param
    (
    [Parameter(Mandatory=$false)][string]$foo
    )

    begin {}
    process {
        try{
            $cmsReplicationResult = Get-CsManagementStoreReplicationStatus | Where-Object UpToDate -ne $true
        }catch{
            throw;
        }
        #walk through collection to build array of failed replication partners
        if ($cmsReplicationResult) {
            #we have failed replication servers
            $cmsTested = $cmsReplicationResult.ReplicaFqdn
        }else{
            $cmsTested = $resources.CMSReplicationExpectedResult
        }

        $cmsResult = ProcessResult -testId $resources.CMSReplicationTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.CMSReplicationErrorMessage -testSuccessMessage $resources.CMSReplicationSuccessMessage -testExpectedValue $resources.CMSReplicationExpectedResult -testValue $cmsTested
    }
    end {
        return $cmsResult
    }
}

function GetAccessEdgeConfiguration{
    [cmdletbinding()]
    Param()
    begin {}
    process {
        #### get Access Edge Configuration ###
        $accessEdgeConfig = Get-CsAccessEdgeConfiguration

        #check AllowOutsideUsers
        ProcessResult -testId $resources.AccessEdgeOutsideUsersTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.AccessEdgeOutsideUsersErrorMessage -testSuccessMessage $resources.AccessEdgeOutsideUsersSuccessMessage -testExpectedValue $resources.AccessEdgeOutsideUsers -testValue $accessEdgeConfig.AllowOutsideUsers
        #check AllowFederatedUsers
        ProcessResult -testId $resources.AccessEdgeFederatedUsersTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.AccessEdgeFederatedUsersErrorMessage -testSuccessMessage $resources.AccessEdgeFederatedUsersSuccessMessage -testExpectedValue $resources.AccessEdgeFederatedUsers -testValue $accessEdgeConfig.AllowFederatedUsers
        #check EnableParnterDiscovery
        ProcessResult -testId $resources.AccessEdgePartnerDiscoveryTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.AccessEdgePartnerDiscoveryErrorMessage -testSuccessMessage $resources.AccessEdgePartnerDiscoverySuccessMessage -testExpectedValue $resources.AccessEdgePartnerDiscovery -testValue $accessEdgeConfig.EnablePartnerDiscovery
        #checkUseDnsSrvRouting
        ProcessResult -testId $resources.AccessEdgeDnsSrvRoutingTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.AccessEdgeDnsSrvRoutingErrorMessage -testSuccessMessage $resources.AccessEdgeDnsSrvRoutingSuccessMessage -testExpectedValue $resources.AccessEdgeDnsSrvRouting -testValue $accessEdgeConfig.RoutingMethod        
    }
    end {}
}

function GetHostingProviderConfiguration{
    [cmdletbinding()]
    Param()
    
    begin {}
    process {
        #### get Hosting Provider Configuration ###
        $hostingProviderConfig = Get-CsHostingProvider | Where-Object ProxyFqdn -eq $resources.HostingProviderProxyFqdn

        #since we can get back multiple objects from Get-CsHostingProvider we perform the filter above. Since the 'Identity' and 'Name' values for this object are subject to change, we just need to verify the ProxyFqdn is set correctly on one of the objects returned.
        if ($hostingProviderConfig){
            #check Proxy FQDN
            ProcessResult -testId $resources.HostingProviderProxyFqdnTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderProxyFqdnErrorMessage -testSuccessMessage $resources.HostingProviderProxyFqdnSuccessMessage -testExpectedValue $resources.HostingProviderProxyFqdn -testValue $hostingProviderConfig.ProxyFqdn
            #check Enablement
            ProcessResult -testId $resources.HostingProviderEnabledTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderEnabledErrorMessage -testSuccessMessage $resources.HostingProviderEnabledSuccessMessage -testExpectedValue $resources.HostingProviderEnabled -testValue $hostingProviderConfig.Enabled
            #check Shared Address Space
            ProcessResult -testId $resources.HostingProviderSharedAddressSpaceTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderSharedAddressSpaceErrorMessage -testSuccessMessage $resources.HostingProviderSharedAddressSpaceSuccessMessage -testExpectedValue $resources.HostingProviderSharedAddressSpace -testValue $hostingProviderConfig.EnabledSharedAddressSpace
            #check Hosts OCS Users
            ProcessResult -testId $resources.HostingProviderHostOCSUsersTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderHostOCSUsersErrorMessage -testSuccessMessage $resources.HostingProviderHostOCSUsersSuccessMessage -testExpectedValue $resources.HostingProviderHostOCSUsers -testValue $hostingProviderConfig.HostsOCSUsers
            #check Verification level
            ProcessResult -testId $resources.HostingProviderVerificationLevelTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderVerificationLevelErrorMessage -testSuccessMessage $resources.HostingProviderVerificationLevelSuccessMessage -testExpectedValue $resources.HostingProviderVerificationLevel -testValue $hostingProviderConfig.VerificationLevel
            #check IsLocal
            ProcessResult -testId $resources.HostingProviderIsLocalTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderIsLocalErrorMessage -testSuccessMessage $resources.HostingProviderIsLocalSuccessMessage -testExpectedValue $resources.HostingProviderIsLocal -testValue $hostingProviderConfig.IsLocal
            
            ### NOTE:check AutoDiscoverUrl obtained from GetTenantInfo function
            ProcessResult -testId $resources.HostingProviderUrlTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderUrlErrorMessage -testSuccessMessage $resources.HostingProviderUrlSuccessMessage -testExpectedValue $tenantInfo -testValue $hostingProviderConfig.AutoDiscoverUrl
        }else{
            #we didn't find a match for the Hosting Provider
            ProcessResult -testId $resources.HostingProviderTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.HostingProviderErrorMesssage
        }

    }
    end {}
}

function GetTenantFederationConfiguration{
    [cmdletbinding()]
    Param()

    begin {}
    process {
        $tenantFedConfig = Get-SfboCsTenantFederationConfiguration
        ProcessResult -testId $resources.TenantSharedSipTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.TenantSharedSipErrorMessage -testSuccessMessage $resources.TenantSharedSipSuccessMessage -testExpectedValue $resources.TenantSharedSip -testValue $tenantFedConfig.SharedSipAddressSpace
    }
    end {}
}

function InvokeSkypeOnlineConnection{
    [cmdletbinding()]
    Param()
    begin{}
    process{
        #determine if Skype for Business PsSession is loaded in memory
        $sessionInfo = Get-PsSession

        #remove any PSSession previously established
        foreach ($sessionItem in $sessionInfo){
            if ($sessionItem.ComputerName.Contains(".online.lync.com")){
                Write-Verbose -Message $resources.PSSessionRemovalMessage
                $sessionItem | Remove-PSSession
            }
        }

        Write-Verbose -Message $resources.NewSkypeOnlineSessionMessage

        try{
            if (!$SkypeOnlineCredentials){
                Write-Output $resources.SFBONoCredsMessage
                if (!$OverrideAdminDomain){
                    $lyncsession = New-CsOnlineSession -ErrorAction SilentlyContinue -ErrorVariable $newOnlineSessionError
                }else{
                    $lyncsession = New-CsOnlineSession -ErrorAction SilentlyContinue -OverrideAdminDomain $TenantDomain -ErrorVariable $newOnlineSessionError
                }
            }else{
                if (!$OverrideAdminDomain){
                    $lyncsession = New-CsOnlineSession -Credential $SkypeOnlineCredentials -ErrorAction SilentlyContinue -ErrorVariable $newOnlineSessionError
                }else{
                    $lyncsession = New-CsOnlineSession -Credential $SkypeOnlineCredentials -OverrideAdminDomain $TenantDomain -ErrorAction SilentlyContinue -ErrorVariable $newOnlineSessionError
                }
            }
        }catch{
            throw $_
        }finally{
            if ($newOnlineSessionError){
                throw $newOnlineSessionError
            }    
        }

        Write-Verbose -Message $resources.ImportingPSSessionMessage
        try{
            Import-PSSession $lyncsession -Prefix Sfbo -ErrorAction SilentlyContinue -ErrorVariable $psSessionError | Out-Null
        }
        catch{
            throw
        }
        
    }
    end{}
}

function ProcessResult{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)][string]$testId,
        [Parameter(Mandatory=$true)][string]$testName,
        [Parameter(Mandatory=$false)]$sourceComputerName,
        [Parameter(Mandatory=$false)]$destinationComputerName,
        [Parameter(Mandatory=$false)][string]$testErrorMessage,
        [Parameter(Mandatory=$false)][string]$testSuccessMessage,
        [Parameter(Mandatory=$true)]$testExpectedValue,    
        [Parameter(Mandatory=$true)]$testValue
    )

    begin {}
    process {
        [array]$outputResult = [PSCustomObject][ordered]@{
            TestId = $testId
            TestName = $testName
            SourceComputerName = $sourceComputerName
            DestinationComputerName = $destinationComputerName
            ErrorMessage = $(if ($testExpectedValue -ne $testValue){$testErrorMessage}else{$testErrorMessage = $null})
            SuccessMessage = $(if ($testExpectedValue -eq $testValue){$testSuccessMessage}else{$testSuccessMessage = $null})
            ExpectedValue = $testExpectedValue
            TestedValue = $testValue
            TestedResult = $(if ($testExpectedValue -ne $testValue){"FAIL"}else{"PASS"})
            TestDate = $(Get-Date)
        }
    }
    end {
        return $outputResult
    }
}

function TestFrontEndServers{
    [cmdletbinding()]
    Param
    ()

    begin {
        $testId = $resources.FeServerPortTestId
    }
    process {
        #find all Edge servers to test FE to EDGE association
        [array]$edgeServers = ((Get-CsService -EdgeServer).Identity).Replace("EdgeServer:","")

        #note: we don't do a Get-CsService -Registrar here because we want the associated FE's for all Edge servers. Some FE's might not have an Edge association defined.
        [array]$poolServers = (((Get-CsService -EdgeServer).DependentServiceList) | Where-Object {$_ -like "Registrar:*"}).Replace("Registrar:","")
        $registrarServers = ($poolServers | ForEach-Object {Get-CsPool -Identity $_}).Computers
        [array]$frontEndToEdgePorts = ($resources.FeServerPortTestList).split(",")
        $edgeServerTestResults = TestTcpPortConnection -Ports $frontEndToEdgePorts -Source $registrarServers -Destination $edgeServers
        $edgeServerTestResults | ForEach-Object {
            ProcessResult -testId $resources.FeServerPortTestId -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -destinationComputerName $_.Destination -testErrorMessage $($resources.FeServerPortTestErrorMessage + $_.Port) -testSuccessMessage $($resources.FeServerPortTestSuccessMessage + $_.Port) -testExpectedValue $resources.PortTestExpected -testValue $_.TestResult
        }
    }
    end {}
}

function CompareFederationBetweenOnlineOnPrem {
    [cmdletbinding()]
    param(

    )
    begin{
        #make sure SFBO connection is established
        $session = Get-PSSession | Where-Object {$_.ComputerName -like "*online.lync.com" -and $_.State -eq "Opened" -and $_.Availability -eq "Available"} -ErrorAction SilentlyContinue
        if (!$session){
            return ProcessResult -testId $resources.CompareFederationSettingsTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.NoSfboConnection
        }
    }
    process{
        if (!($fedResult = Get-SfboCsTenantFederationConfiguration).AllowFederatedUsers){
            #federation is turned off in the tenant
            return ProcessResult -testId $resources.CompareFederationSettingsTestId -testName $PSCmdlet.CommandRuntime -testErrorMessage $resources.CompareFederationSettingsOnlineFedError -testExpectedValue $resources.CompareFederationSettingsAllowFed -testValue $fedResult.AllowFederatedUsers
        }else{
            ProcessResult -testId $resources.CompareFederationSettingsTestId -testName $PSCmdlet.CommandRuntime -testSuccessMessage $resources.CompareFederationSettingsSuccessMessage -testExpectedValue $resources.CompareFederationSettingsAllowFed -testValue $fedResult.AllowFederatedUsers
        }

    }
    end{}

}

function TestTcpPortConnection{
    [cmdletbinding()]
    param(
        [Parameter(mandatory=$true)][array]$Source,
        [Parameter(mandatory=$true)][array]$Destination,
        [Parameter(mandatory=$true)][array]$Ports,
        [Parameter(Mandatory=$false)][int32]$TimeoutInMs = 1000
    )
    begin{}
    process{
        ForEach ($d in $Destination){
            #we should remove the source server from the array just in case since we don't want to test from/to the same server
            If ($Source.Contains($d)){
                Write-Verbose -Message $resources.PortTestRemoveDestinationMessage
                [System.Collections.ArrayList]$NewSource = $Source #alternatively we could use $NewSource = $Source -ne $d
                $NewSource.Remove($d)
            }else{
                $NewSource = $Source
            }
            ForEach ($p in $Ports){
                try{
                    [array]$portTestResult += Invoke-Command -ScriptBlock {
                        $Socket = New-Object System.Net.Sockets.TCPClient;
                        $Connection = $Socket.BeginConnect($args[0],$args[1],$null,$null);
                        $Connection.AsyncWaitHandle.WaitOne($args[2],$false)  | Out-Null;
                        $bucket = [PSCustomObject]@{
                            Source = ($env:COMPUTERNAME).ToLower()
                            Destination = ($args[0]).ToLower()
                            Port = $args[1]
                            TestResult = $(if($Socket.Connected -eq $true){"Connected"}else{"Not Connected"})
                        }
                        $Socket.Close | Out-Null;
                        Return $bucket;
                        $bucket = $null;
                    } -ComputerName $NewSource -Args $d,$p,$TimeoutInMs -ErrorAction SilentlyContinue -ErrorVariable $testTcpError
                }catch{
                    ProcessResult -testId $testId -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -destinationComputerName $d -testErrorMessage $_ -testExpectedValue $resources.PortTestExpected -testValue "Exception"
                }finally{
                    if ($testTcpError){
                        ProcessResult -testId $testId -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -destinationComputerName $d -testErrorMessage $_ -testExpectedValue $resources.PortTestExpected -testValue "Error"
                    }
                }
            }

            
        }
    }
    end{
        return $portTestResult
    }
}

function TestServerPatchVersion{
    [cmdletbinding()]
    Param()
    begin {
        #get ServicesToPatch from resources file. to scan for more simply add them to the resources file then add to the switch block below for each service's text to display.
        [array]$servicesToPatch = $resources.ServicesToPatch.split(",")
    }
    process {
        foreach ($serviceItem in $servicesToPatch){
            switch ($serviceItem){
                Registrar {$serviceFriendlyName = $resources.FeServiceFriendlyName;$serviceName = $resources.FeServiceName;$patchTestId = $resources.FeServerPatchVersionTestId;$patchErrorMessage = $($resources.FeServerPatchErrorMessage + $resources.FeServiceFriendlyName);$patchSuccessMessage = $($resources.FeServerPatchSuccessMessage + $resources.FeServiceFriendlyName);$patchVersion = $resources.FeServerPatchVersion}
                MediationServer {$serviceFriendlyName = $resources.MedServiceFriendlyName;$serviceName = $resources.MedServiceName;$patchTestId = $resources.MedServerPatchVersionTestId;$patchErrorMessage = $($resources.MedServerPatchErrorMessage = $resources.MedServiceFriendlyName);$patchSuccessMessage = $($resources.MedServerPatchSuccessMessage + $resources.MedServiceFriendlyName);$patchVersion = $resources.MedServerPatchVersion}
            }
            
            $expr = "Get-CsService -$serviceItem"
            $servers = (Invoke-Expression $expr).Identity.Replace($serviceItem + ":","")
            try{
                #powershell remoting used to fan out for speed
                $patchResult = (Invoke-Command -ScriptBlock {Get-CsServerPatchVersion} -ComputerName $servers -ErrorAction SilentlyContinue -ErrorVariable patchError | Where-Object ComponentName -eq $serviceFriendlyName)
            }catch{
                ProcessResult -testId $patchTestId -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -testErrorMessage $_ -testExpectedValue $patchVersion -testValue "Exception"
            }finally{
                if ($patchError){
                    ProcessResult -testId $patchTestId -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -testErrorMessage $patchError -testExpectedValue $patchVersion -testValue "Error"
                }
            }
            
            
            #process results for this service item
            $patchResult | ForEach-Object {
                ProcessResult -testId $patchTestId -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -testErrorMessage $patchErrorMessage -testSuccessMessage $patchSuccessMessage -testExpectedValue $patchVersion -testValue $_.Version
            }
        }
    }
    end {}
}

function GetTenantInfo{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)][ValidateNotNull()][string] $TenantDomain,
        [Parameter(Mandatory = $false)][Switch] $Edog = $false,
        [Parameter(Mandatory = $false)][string] $ForestFQDN,
        [Parameter(Mandatory = $false)][string] $altForestFQDN = $null,
        [Parameter(Mandatory = $false)][string] $acsFQDN = $null
    )
    begin{
        $ErrorActionPreference = "Stop"
    }

    process{
        if ([System.String]::IsNullOrEmpty($ForestFQDN)){
            if ($Edog)
            {
                $ForestFQDN = "webdir.tip.lync.com"
            }
            else
            {
                $ForestFQDN = "webdir.online.lync.com"
            }
        }

        if ([System.String]::IsNullOrEmpty($acsFQDN)){
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
        try{
            $req = [Net.WebRequest]::Create("https://$acsFQDN/metadata/json/1?realm=$TenantDomain")
            Write-Verbose ("Getting ACS json document from {0} ..." -f $req.RequestUri)
            $rsp = $req.GetResponse()
            $str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
            $TenantID = ($str | ConvertFrom-Json).realm
        }catch [System.Net.WebException]{
            $webEx = ($Error[0].Exception.InnerException) -as [System.Net.WebException]
            if (($webEx -ne $null) -and ($webEx.Status -eq [System.Net.WebExceptionStatus]::ProtocolError)){
                throw "Domain $TenantDomain is not registired with ACS/O365"
            }
            throw
        }catch{
            throw
        }

        # Now get response from Lync SfB autodiscover service
        $req = [Net.WebRequest]::Create("https://$ForestFQDN/AutoDiscover/AutoDiscoverservice.svc/root?originalDomain=$TenantDomain")
        $rsp = $req.GetResponse()
        $str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
        #Write-Verbose $str

        $json = ($str | ConvertFrom-Json)
        $self = ($json._links.self.href -as [System.URI]).Host
        if ([System.String]::IsNullOrEmpty($json._links.redirect.href)){
            # Since we were not redirected to a different forest, we need to make sure
            # that domain is actually in Lync/SfB online by asking some other forest
            if ([System.String]::IsNullOrEmpty($altForestFQDN)){
                switch ($self){
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
                    default{
                        if ($self.EndsWith("online.lync.com")){
                            $altForestFQDN = "webdir0m.online.lync.com"
                        }elseif ($self.EndsWith("tip.lync.com")){
                            $altForestFQDN = "webdir0d.tip.lync.com"
                        }else{
                            throw "Unknown forest FQDN: $self"
                        }
                    }
                }
                Write-Verbose "Selected forest $altForestFQDN for second check"
            }else{
                Write-Verbose "Using forest $altForestFQDN for second check"
            }

            $req = [Net.WebRequest]::Create("https://$altForestFQDN/AutoDiscover/AutoDiscoverservice.svc/root?originalDomain=$TenantDomain")
            $rsp = $req.GetResponse()
            $str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
            #Write-Verbose $str

            $json = ($str | ConvertFrom-Json)
            $altSelf = ($json._links.self.href -as [System.URI]).Host
        }
        if ([System.String]::IsNullOrEmpty($json._links.redirect.href)){
            throw "Domain $TenantDomain is not in any known SfB/Lync online forest (reported by $self and $altSelf)"
        }

        $redirect = ($json._links.redirect.href -as [System.URI]).Host
        Write-Verbose "Domain $TenantDomain is in $redirect, reported by $self"
        $tenantForest = $redirect

        $req = [Net.WebRequest]::Create("https://$redirect/WebTicket/WebTicketService.svc/mex")
        $req.Headers.Add("X-User-Identity", (-join "user@",$TenantDomain))
        $rsp = $req.GetResponse()
        $str = (new-object System.IO.StreamReader ($rsp.GetResponseStream())).ReadToEnd()
        #Write-Verbose $str

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
            af="urn:component:Microsoft.Rtc.WebAuthentication.2010"
        }

        $TenantOAuth = (Select-Xml -Namespace $namespace -Content $str -XPath "//af:OAuth/@af:authorizationUri").Node.Value

        #Write Output Oject
        $properties = @{
            'TenantDomain'=$TenantDomain;
            'TenantID'=$TenantID;
            'TenantForest'=$TenantForest;
            'TenantOAuth'=$TenantOAuth;
        }
        $object = New-Object -TypeName PSObject -Property $properties

        #prepare autodiscoverurl
        $autodiscoverUrl = "https://$($object.TenantForest)/Autodiscover/AutodiscoverService.svc/root"
    }
    end{
        return $autodiscoverUrl
    }
}
