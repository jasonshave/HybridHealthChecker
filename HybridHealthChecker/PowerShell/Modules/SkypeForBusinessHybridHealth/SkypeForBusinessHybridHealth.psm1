<#
function Get-SkypeForBusinessHybridHealth {
    Write-Host -ForegroundColor Green "This command has been deprecated. Starting new command: Invoke-SkypeForBusinessHybridHealthCheck"
    Invoke-SkypeForBusinessHybridHealthCheck
}
#>

function Invoke-SkypeForBusinessHybridHealthCheck {
    ##############################
    #.SYNOPSIS
    #Performs several standardized tests for Skype for Business Hybrid connectivity to Skype for Business Online.
    #
    #.DESCRIPTION
    #Using XAML with WPF controls and .NET runspaces we build a UI to interface with the various functions'
    # which perfor the necessary tests. Output is displayed by modifying abstracted variables which reference'
    # the XAML controls scraped at runtime. Name tags in the XAML which represent WPF controls are manipulated'
    # using a .NET DispatcherTimer. The application presents a splash screen, then the main UI.
    #
    #.EXAMPLE
    # Invoke-SkypeForBusinessHybridHealthCheck
    #
    #.NOTES
    # Source code available at: https://github.com/jasonshave/HybridHealthChecker
    ##############################

    #primary sync'd hashtable for variables and object references
    $Global:uiHash = [hashtable]::Synchronized(@{})

    #store runspaces in jobs array so we can dispose of them when we're done
    $Jobs = @{}
    $uiHash.Jobs = $Jobs
    $Hosts = @{}
    $uiHash.Hosts = $Hosts
    $RunspaceOutput = @{}
    $uiHash.RunspaceOutput = $RunspaceOutput
    
    #this is where we store all our results from the tests
    $uiHash.resultsHash = $null
    
    #sync'd hash table for variables we need in each runspace
    $Global:variableHash = [hashtable]::Synchronized(@{})

    $variableHash.LyncTools = "https://technet.microsoft.com/en-us/library/gg398665(v=ocs.15).aspx"
    $variableHash.SfbTools = "https://technet.microsoft.com/en-ca/library/dn933921.aspx"
    $variableHash.SfbOTools = "https://www.microsoft.com/en-us/download/details.aspx?id=39366"
    $variableHash.rootPath = Split-Path (Get-module SkypeForBusinessHybridHealth).path
    $variableHash.requiredModules = @("SkypeOnlineConnector","SkypeForBusiness","Lync")

    foreach ($moduleName in $variableHash.requiredModules) {
        $variableHash.($moduleName) = Get-Module $moduleName
    }
    
    #DISPLAY SPLASH#
    $splashBlock = {
        $uiHash.Hosts.("RspSplashScreen") = $Host
        
        Add-Type -AssemblyName PresentationFramework
        
        $uiContent = Get-Content -Path ($variableHash.rootPath + "\Splash.xaml")
        
        [xml]$xAML = $uiContent -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'
        $xmlReader = (New-Object System.Xml.XmlNodeReader $xAML)
        $uiHash.Splash = [Windows.Markup.XamlReader]::Load($xmlReader)

        $xAML.SelectNodes("//*[@Name]") | ForEach-Object {
            $uiHash.Add($_.Name, $uiHash.Splash.FindName($_.Name))
        }

        #region EVENTS#

            $uiHash.Splash.Add_SourceInitialized(
                {
                    $uiHash.picSplash1.Source = ($variableHash.rootPath + "\Skype_for_Business_Logo.png")
                }
            )

            $uiHash.Splash.Add_MouseRightButtonDown(
                {
                    $uiHash.Splash.Close()
                }
            )
        #end region EVENTS#

        $uiHash.Splash.ShowDialog() | Out-Null
    }

    Invoke-NewRunspace -codeBlock $splashBlock -RunspaceHandleName RspSplashScreen

    #DISPLAY MAIN WINDOW#
    $mainWindow = {
        $uiHash.Hosts.("RspMainUi") = $Host
        Add-Type -AssemblyName PresentationFramework
        
        $uiContent = Get-Content -Path ($variableHash.rootPath + "\MainWindow.xaml")
        
        [xml]$xAML = $uiContent -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window'
        $xmlReader = (New-Object System.Xml.XmlNodeReader $xAML)
        $uiHash.Window = [Windows.Markup.XamlReader]::Load($xmlReader)

        $xAML.SelectNodes("//*[@Name]") | ForEach-Object {
            $uiHash.Add($_.Name, $uiHash.Window.FindName($_.Name))
        }

        #region EVENTS#
        
            $uiHash.Window.Add_SourceInitialized(
                {
                    $uiHash.picSfb.Source = ($variableHash.rootPath + "\sfb.png")
                    $uiHash.Window.Icon = ($variableHash.rootPath + "\sfb.png")
                    $uiHash.txtVersion.Text = ((Get-Module SkypeForBusinessHybridHealth).Version).toString()

                    $uiHash.comboVersion.ItemsSource = @("Skype for Business Server 2015","Lync Server 2013")
                    $uiHash.comboVersion.SelectedIndex = 0
                    $uiHash.ComboVersionSelectedValue = $uiHash.comboVersion.SelectedValue

                    $uiHash.Status = "Ready"
                    $uiHash.StatusColor = "White"
                    $uiHash.ProgressBarVisibility = "Hidden"
                    $uiHash.ConnectIsEnabled = $false
                    $uiHash.SfboStatusText = "You must provide the required information to connect to Skype for Business Online."
                    $uiHash.AdminDomainIsChecked = $false
                    $uiHash.OnPremModuleNameText = "Skype for Business PowerShell Module"

                    Invoke-CheckModules

                    $updateBlock = {
                        #update the results grid with our data via XAML binding attribute called "resultsData"
                        $uiHash.Window.Resources["resultsData"] = $uiHash.resultsHash

                        #update status bar
                        $uiHash.barStatus.Value = $uiHash.ProgressBarStatus
                        $uiHash.barStatus.Visibility = $uiHash.ProgressBarVisibility

                        #update text blocks
                        $uiHash.txtStatus1.Text = $uiHash.Status
                        $uiHash.txtStatus1.Foreground = $uiHash.StatusColor
                        $uiHash.txtSfboStatus.Text = $uiHash.SfboStatusText
                        $uiHash.txtUserNotify.Text = $uiHash.UserNotifyText
                        $uiHash.txtOnPremModuleName.Text = $uiHash.OnPremModuleNameText

                        #update buttons
                        $uiHash.btnConnect.IsEnabled = $uiHash.ConnectIsEnabled
                        $uiHash.btnAdminInstalled.IsEnabled = $uiHash.AdminInstalledIsEnabled
                        $uiHash.btnAdminInstalled.Content = $uiHash.AdminInstalledContent
                        $uiHash.btnSFBOAdminInstalled.IsEnabled = $uiHash.SFBOAdminInstalledIsEnabled

                        if ([string]::IsNullOrEmpty($uiHash.Username) -and [string]::IsNullOrEmpty($uiHash.TenantDomainText) -and (!($uiHash.btnAdminInstalled.IsEnabled)) -and (!($uiHash.btnSFBOAdminInstalled.IsEnabled))) {
                            $uiHash.btnStartTests.IsEnabled = $true
                        }
                    }

                    # Create timer to handle updating the grid
                    $timer = new-object System.Windows.Threading.DispatcherTimer
                    $timer.Interval = [TimeSpan]"0:0:0:0.30"
                    $timer.Add_Tick($updateBlock)
                    $timer.Start()
                }
            )

            $uiHash.Window.Add_Closing(
                {
                    Remove-PSSession $uiHash.SfboSession
                }
            )

            $uiHash.Window.Add_Closed(
                {
                    #this is where we do our cleanup to prevent memory leaks.
                    #we don't want these runspaces to consume memory if they're
                    #not in use even after the window has been closed.
                    foreach ($rsp in $uiHash.Jobs) {
                        $uiHash.Jobs.$rsp.Dispose()
                    }
                }
            )

            $uiHash.Window.Add_Loaded(
                {
                    $uiHash.Splash.Dispatcher.Invoke([action]{$uiHash.Splash.Close()})
                }
            )

            $uiHash.btnStartDebug.Add_Click(
                {
                    #testing goes here
                }
            )

            $uiHash.btnConnect.Add_Click(
                {
                    $connectBlock = {
                        InvokeSkypeOnlineConnection -authFromGui
                    }

                    Invoke-NewRunspace -codeBlock $connectBlock -RunspaceHandleName "RspSfboConnect"
                }
            )

            $uiHash.comboVersion.Add_SelectionChanged(
                {
                    $uiHash.ComboVersionSelectedValue = $uihash.comboVersion.SelectedValue
                    Invoke-CheckModules
                }
            )

            $uiHash.btnAdminInstalled.Add_Click(
                {
                    switch ($uiHash.ComboVersionSelectedValue) {
                        "Skype for Business Server 2015" { Start-Process $variableHash['SfbTools'] }
                        "Lync Server 2013" { Start-Process $variableHash['LyncTools'] }
                    }
                }
            )

            $uiHash.btnSFBOAdminInstalled.Add_Click(
                {
                    Start-Process $variableHash['SfbOTools']
                }
            )

            $uiHash.navFeedback.Add_Click(
                {
                    Start-Process $uiHash.navFeedback.NavigateUri
                }
            )

            $uiHash.navGitHub.Add_Click(
                {
                    Start-Process $uiHash.navGitHub.NavigateUri
                }
            )
                
            $uiHash.btnStartTests.Add_Click(
                {
                    #clear previous test results and change the view to the Results tab
                    $uiHash.resultsHash = $null
                    $uiHash.tabMain.SelectedIndex = 1

                    $testCode = {
                        $uiHash.Status = "Running tests..."
                        $uiHash.StartTestButtonIsEnabled = $false
                        $uiHash.ProgressBarVisibility = "Visible"

                        #test execution
                        $uiHash.ProgressBarStatus = 17
                        GetCmsReplicationStatus
                        
                        $uiHash.ProgressBarStatus = 33
                        GetHostingProviderConfiguration
                        
                        $uiHash.ProgressBarStatus = 50
                        GetAccessEdgeConfiguration

                        $uiHash.ProgressBarStatus = 67
                        TestFEToEdgePorts
                        
                        $uiHash.ProgressBarStatus = 84
                        GetSharedSipAddressSpace

                        #re-enable the button :)
                        $uiHash.ProgressBarStatus = 100
                        $uiHash.ProgressBarVisibility = "Hidden"
                        $uiHash.StartTestButtonIsEnabled = $true

                        $uiHash.Status = "Finished!"
                        $uiHash.StatusColor = "White"

                        $uiHash.CodeBlockError = $Error
                    }

                    Invoke-NewRunspace -codeBlock $testCode -RunspaceHandleName "RspStartTests"

                }
            )

            $uiHash.chkAdminDomain.Add_Checked(
                {
                    $uiHash.AdminDomainIsChecked = $uiHash.chkAdminDomain.IsChecked
                    ValidateSfboItems
                }
            )

            $uiHash.chkAdminDomain.Add_UnChecked(
                {
                    $uiHash.AdminDomainIsChecked = $uiHash.chkAdminDomain.IsChecked
                    ValidateSfboItems
                }
            )

            $uiHash.txtTenantDomain.Add_TextChanged(
                {
                    $uiHash.TenantDomainText = $uiHash.txtTenantDomain.Text
                    ValidateSfboItems
                }
            )

            $uiHash.txtUsername.Add_TextChanged(
                {
                    $uiHash.Username = $uiHash.txtUsername.Text
                    ValidateSfboItems                
                }
            )

            $uiHash.txtPassword.Add_TextInput( 
                {
                    ValidateSfboItems   
                }
            )
        

        #end region

        $uiHash.Window.ShowDialog() | Out-Null
        $uiHash.Error = $Error
        
    }

    Invoke-NewRunspace -codeBlock $mainWindow -RunspaceHandleName RspMainUi
    
    Write-Host "Attempting to start UI..." -ForegroundColor Green
    
}

# INTERNAL FUNCTIONS #

function ValidateSfboItems {

    if ([string]::IsNullOrEmpty($uiHash.TenantDomainText) -or [string]::IsNullOrEmpty($uiHash.Username)) {
        $uiHash.ConnectIsEnabled = $false
        return
    }

    #override admin domain
    #if ($uiHash.AdminDomainIsChecked -and (![string]::IsNullOrEmpty($uiHash.Username)) -and (![string]::IsNullOrEmpty($uiHash.TenantDomainText))) {
    if ($uiHash.AdminDomainIsChecked) {
        try {
            $validateUsername = [System.Net.Mail.MailAddress]($uiHash.Username)
            $uiHash.UserNotifyText = "We'll use: " + $validateUsername
            $uihash.ValidatedUserName = $validateUsername
            $uihash.ConnectIsEnabled = $true
            return
        } catch {
            $uiHash.UserNotifyText = "NOTE: The username should be in UPN format (i.e. username@domain.com)"
            return
        }
    }
    #use standard login method
    #if (!$uiHash.AdminDomainIsChecked -and (![string]::IsNullOrEmpty($uiHash.Username)) -and (![string]::IsNullOrEmpty($uiHash.TenantDomainText))) {
    if (!$uiHash.AdminDomainIsChecked) {
            $uiHash.UserNotifyText = "We'll use: " + $uiHash.Username + "@" + $uiHash.TenantDomainText + ".onmicrosoft.com"
            $uiHash.ValidatedUserName = $uiHash.Username + "@" + $uiHash.TenantDomainText + ".onmicrosoft.com"
            $uiHash.ConnectIsEnabled = $true
    } else {
        $uiHash.UserNotifyText = ""
    }
}

function Invoke-NewRunspace {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)][scriptblock]$codeBlock,
        [parameter(Mandatory=$true)][string]$RunspaceHandleName
    )

    $testingRunspace = [runspacefactory]::CreateRunspace()
    $testingRunspace.ApartmentState = "STA"
    $testingRunspace.ThreadOptions = "ReuseThread"
    $testingRunspace.Open()
    $testingRunspace.SessionStateProxy.SetVariable("uiHash",$uiHash)
    $testingRunspace.SessionStateProxy.SetVariable("variableHash",$variableHash)

    $uiHash.RunspaceOutput.($RunspaceHandleName) = New-Object System.Management.Automation.PSDataCollection[psobject]

    $testingCmd = [PowerShell]::Create().AddScript($codeBlock)
    $testingCmd.Runspace = $testingRunspace
    
    $testingHandle = $testingCmd.BeginInvoke($uiHash.RunspaceOutput.($RunspaceHandleName),$uiHash.RunspaceOutput.($RunspaceHandleName))

    #store the handle in the global sync'd hashtable; arraylist we'll use the window.closed() event to clean up
    $uiHash.Jobs.($RunspaceHandleName) = $testingHandle
}

function Invoke-CheckModules {
    #detect modules for on-prem pieces
    switch ($uiHash.ComboVersionSelectedValue) {
        "Skype for Business Server 2015" { 
            $mName = "SkypeForBusiness"
            $uiHash.OnPremModuleNameText = "Skype for Business PowerShell Module"
        }
        "Lync Server 2013" {
            $mName = "Lync"
            $uiHash.OnPremModuleNameText = "Lync Server 2013 PowerShell Module"
        }
        Default { #need to verify we need this still?
            $mName = "Not found"
            $uiHash.Status = "Could not locate either module for Skype or Lync admin tools."
        }
    }

    if (!($variableHash.$mName)) {
        $uiHash.AdminInstalledIsEnabled = $true
        $uiHash.AdminInstalledContent = "More Info"
    } else {
        $uiHash.AdminInstalledIsEnabled = $false
        $uiHash.AdminInstalledContent = "Installed"
    }

    #detect if SFBO module is available
    if (!$variableHash.SkypeOnlineConnector) {
        $uiHash.SFBOAdminInstalledIsEnabled = $true
        $uiHash.SFBOAdminInstalledContent = "More Info"
    }
}

function GetCmsReplicationStatus {

    $testExpectedValue = "None"

    $cmsReplicationResult = Get-CsManagementStoreReplicationStatus -ErrorVariable $testMessage
    if (!($cmsReplicationResult)) {
        $testValue = "Failed to execute test"
    }

    $failedReplicas = $cmsReplicationResult | Where-Object UpToDate -eq $False
    if ($failedReplicas) {
        #we have failed replication servers
        [string]$testValue = $failedReplicas.ReplicaFqdn | ForEach-Object {$_ + "`r"}
        $testMessage = "CMS Replica not up to date"
    } else {
        #all is okay
        $testValue = "None"
        $testMessage = "All CMS replicas are up to date"
    }

    [array]$objResult = ProcessResult -testName "GetCmsReplicationStatus" -testMessage $testMessage -testExpectedValue $testExpectedValue -testValue $testValue
    
    return $objResult

}

function GetAccessEdgeConfiguration {
    [cmdletbinding()]
    Param()
    begin {}
    process {
        #### get Access Edge Configuration ###
        $accessEdgeConfig = Get-CsAccessEdgeConfiguration

        #check AllowOutsideUsers
        $objResult = ProcessResult -testName 'Access Edge: AllowOutsideUsers' -testExpectedValue $true -testValue $accessEdgeConfig.AllowOutsideUsers
        #check AllowFederatedUsers
        $objResult = ProcessResult -testName 'Access Edge: AllowFederatedUsers' -testExpectedValue $true -testValue $accessEdgeConfig.AllowFederatedUsers
        #check EnableParnterDiscovery
        $objResult = ProcessResult -testName 'Access Edge: PartnerDiscovery' -testExpectedValue $true -testValue $accessEdgeConfig.EnablePartnerDiscovery
        #checkUseDnsSrvRouting
        $objResult = ProcessResult -testName 'Access Edge: UseDnsSrvRouting' -testExpectedValue UseDnsSrvRouting -testValue $accessEdgeConfig.RoutingMethod        
    }
    end {}
}

function GetHostingProviderConfiguration {
    [cmdletbinding()]
    Param()
    
    begin {
        [string]$tenantDomain = $uiHash.TenantDomainText + ".onmicrosoft.com"
        $uiHash.tenantInfo = GetTenantInfo -TenantDomain $tenantDomain
        if ([string]::IsNullOrEmpty($uiHash.tenantInfo)){
            ProcessResult -testName 'Obtain hosting provider URL' -testMessage "Error retrieving tenant domain using GetTenantInfo function!" -testExpectedValue "(Office 365 Admin URL)" -testValue "Null"
            return
        }
    }
    process {
        #### get Hosting Provider Configuration ###
        $hostingProviderConfig = Get-CsHostingProvider | Where-Object ProxyFqdn -eq 'sipfed.online.lync.com'

        #we will accept this alternate:
        if ($hostingProviderConfig.AutoDiscoverUrl -eq "https://webdir.online.lync.com/AutoDiscover/AutoDiscoverService.svc/root") {
            $uiHash.tenantInfo = $hostingProviderConfig.AutoDiscoverUrl
        }

        #since we can get back multiple objects from Get-CsHostingProvider we perform the filter above. Since the 'Identity' and 'Name' values for this object are subject to change, we just need to verify the ProxyFqdn is set correctly on one of the objects returned.
        if ($hostingProviderConfig) {
            #check Proxy FQDN
            ProcessResult -testName 'Hosting Provider: ProxyFqdn'  -testExpectedValue 'sipfed.online.lync.com' -testValue $hostingProviderConfig.ProxyFqdn
            #check Enablement
            ProcessResult -testName 'Hosting Provider: Enabled' -testExpectedValue $true -testValue $hostingProviderConfig.Enabled
            #check Shared Address Space
            ProcessResult -testName 'Hosting Provider: SharedAddressSpace' -testExpectedValue $true -testValue $hostingProviderConfig.EnabledSharedAddressSpace
            #check Hosts OCS Users
            ProcessResult -testName 'Hosting Provider: HostOcsUsers' -testExpectedValue $true -testValue $hostingProviderConfig.HostsOCSUsers
            #check Verification level
            ProcessResult -testName 'Hosting Provider: VerificationLevel' -testExpectedValue 'UseSourceVerification' -testValue $hostingProviderConfig.VerificationLevel
            #check IsLocal
            ProcessResult -testName 'Hosting Provider: IsLocal' -testExpectedValue $false -testValue $hostingProviderConfig.IsLocal
            ### NOTE:check AutoDiscoverUrl obtained from GetTenantInfo function
            ProcessResult -testName 'Hosting Provider: AutoDiscoverUrl' -testExpectedValue $uiHash.tenantInfo -testValue $hostingProviderConfig.AutoDiscoverUrl
        } else {
            #we didn't find a match for the Hosting Provider
            ProcessResult -testName 'Hosting Provider: Error' -testMessage "There was an error obtaining the hosting provider information"
        }

    }
    end {}
}

function GetSharedSipAddressSpace{
        #need to check the PSSession and import it
        $uiHash.Status = "Starting GetSharedSipAddressSpace..."
        Start-Sleep -Seconds 10
        if ($uiHash.SfboSession.State -eq "Opened" -and $uiHash.SfboSession.Availability -eq "Available") {
            #import the PSSession since it's healthy
            $uiHash.Status = "Attempting to import the PSSession..."
            Start-Sleep -Seconds 10
            
            try {
                $uiHash.PSSession = Import-PSSession $uiHash.SfboSession -Prefix Sfbo -AllowClobber
            } catch {
                $uiHash.Status = $_.Exception.Message
            }
            
        } else {
            $uiHash.Status = "Error importing remote PowerShell session due to a broken or stale session. Try to re-authenticate by closing the application and trying again."
            Start-Sleep -Seconds 5
            ProcessResult -testName GetSharedSipAddressSpace -testExpectedValue $true -testValue "Error" -testMessage $uiHash.Status
        }

        $tenantFedConfig = Get-SfboCsTenantFederationConfiguration
        ProcessResult -testName GetSharedSipAddressSpace -testExpectedValue $true -testValue $tenantFedConfig.SharedSipAddressSpace
}

function InvokeSkypeOnlineConnection{
    if (!$uiHash.ValidatedUserName) {
        $uiHash.Status = "Error detected. Cannot determine username."
        return
    }

    $uihash.ConnectIsEnabled = $false
    $uiHash.ProgressBarStatus = "50"
    $uiHash.ProgressBarVisibility = "Visible"
    $uiHash.Status = "Attempting to authenticate to Skype for Business Online..."
    $uiHash.SfboStatusText = "Connecting..."

    try {

        if ($uiHash.AdminDomainIsChecked) {
            $uiHash.SfboSession = New-CsOnlineSession -UserName $uiHash.ValidatedUserName -OverrideAdminDomain ($uiHash.TenantDomainText + ".onmicrosoft.com") -ErrorAction SilentlyContinue -WarningAction SilentlyContinue                
        } else {
            $uiHash.SfboSession = New-CsOnlineSession -UserName $uiHash.ValidatedUserName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        $uiHash.SfboStatusText = "Successfully authenticated to Skype for Business Online. Waiting to start tests before importing the PSSession..."

        #$uiHash.Status = "Attempting to import remote PowerShell session..."
        #$uiHash.ProgressBarStatus = "60"
        #$uiHash.PSSessionImportResult = Import-PSSession $uiHash.SfboSession -Prefix Sfbo -ErrorAction SilentlyContinue

    } catch [System.ArgumentNullException] {

        $uiHash.SfboStatusText = "Could not create the session. Possibly due to a bad username/password."
        $uiHash.ConnectIsEnabled = $true
        $uiHash.Status = "Ready"
        return

    } catch {

        $uihash.SfboStatusText = $_.Exception.Message
        $uiHash.ConnectIsEnabled = $true

    }

    $uiHash.ProgressBarVisibility = "Hidden"
    $uiHash.ProgressBarStatus = "0"
    $uiHash.Status = "Ready"

        #validate SFBO connection
        #if ($uiHash.PSSessionImportResult) {
        #    $uiHash.SfboStatusText = "Connected to Skype for Business Online"
        #}
}

function TestFEToEdgePorts {
        #find all Edge servers to test FE to EDGE association
        [array]$edgeServers = ((Get-CsService -EdgeServer).Identity).Replace("EdgeServer:","")

        #note: we don't do a Get-CsService -Registrar here because we want the associated FE's for all Edge servers. Some FE's might not have an Edge association defined.
        [array]$poolServers = (((Get-CsService -EdgeServer).DependentServiceList) | Where-Object {$_ -like "Registrar:*"}).Replace("Registrar:","")
        $registrarServers = ($poolServers | ForEach-Object {Get-CsPool -Identity $_}).Computers
        [array]$frontEndToEdgePorts = 443,4443,5061,5062,8057,50001,50002,50003

        $edgeServerTestResults = TestTcpPortConnection -Ports $frontEndToEdgePorts -Source $registrarServers -Destination $edgeServers
        $edgeServerTestResults | ForEach-Object {

            if ($_.TestResult -eq "Connected") {
                #success; write it out
                $testMessage = "Successfully connected to {0} from {1} on port {2}." -f $_.Destination, $_.Source, $_.Port
            } else {
                $testMessage = "Unable to establish TCP connection from {0} to {1} on {2}." -f $_.Source, $_.Destination, $_.Port
            }
            
            ProcessResult -testName TestFEtoEdgePorts -sourceComputerName $_.PSComputerName -destinationComputerName $_.Destination -testMessage $testMessage -testValue $_.TestResult -testExpectedValue "Connected"
        }
}

function TestTcpPortConnection{
    [cmdletbinding()]
    param(
        [Parameter(mandatory=$true)][array]$Source,
        [Parameter(mandatory=$true)][array]$Destination,
        [Parameter(mandatory=$true)][array]$Ports,
        [Parameter(Mandatory=$false)][int32]$TimeoutInMs = 1000
    )
    begin {}
    process {
        ForEach ($d in $Destination) {
            #we should remove the source server from the array just in case since we don't want to test from/to the same server
            If ($Source.Contains($d)) {
                [System.Collections.ArrayList]$NewSource = $Source #alternatively we could use $NewSource = $Source -ne $d
                $NewSource.Remove($d)
            } else {
                $NewSource = $Source
            }
            ForEach ($p in $Ports) {
                try {
                    $uiHash.Status = "Testing TCP connection from Front-End servers to {0} using port {1}..." -f $d, $p
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
                } catch {
                    ProcessResult -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -destinationComputerName $d -testErrorMessage $_ -testExpectedValue $resources.PortTestExpected -testValue "Exception"
                } finally {
                    if ($testTcpError){
                        ProcessResult -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -destinationComputerName $d -testErrorMessage $_ -testExpectedValue $resources.PortTestExpected -testValue "Error"
                    }
                }
            }

            
        }
    }
    end{
        return $portTestResult
    }
}

function TestServerPatchVersion {
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
                ProcessResult -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -testErrorMessage $_ -testExpectedValue $patchVersion -testValue "Exception"
            }finally{
                if ($patchError){
                    ProcessResult -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -testErrorMessage $patchError -testExpectedValue $patchVersion -testValue "Error"
                }
            }
            
            
            #process results for this service item
            $patchResult | ForEach-Object {
                ProcessResult -testName $PSCmdlet.CommandRuntime -sourceComputerName $_.PSComputerName -testErrorMessage $patchErrorMessage -testSuccessMessage $patchSuccessMessage -testExpectedValue $patchVersion -testValue $_.Version
            }
        }
    }
    end {}
}

function GetTenantInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)][ValidateNotNull()][string] $TenantDomain,
        [Parameter(Mandatory = $false)][Switch] $Edog = $false,
        [Parameter(Mandatory = $false)][string] $ForestFQDN,
        [Parameter(Mandatory = $false)][string] $altForestFQDN = $null,
        [Parameter(Mandatory = $false)][string] $acsFQDN = $null
    )
    begin{
        #$ErrorActionPreference = "Stop"
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
                $uiHash.Status = "Domain $TenantDomain is not registired with ACS/O365"
                return;
            } else {
                $uiHash.Status = "There was an exception getting the URL for the admin domain in Office 365!"
                return;
            }
        }catch{
            $uiHash.Status = "There was an exception getting the URL for the admin domain in Office 365!"
            return;
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

function ProcessResult{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)][string]$testName,
        [Parameter(Mandatory=$false)]$sourceComputerName,
        [Parameter(Mandatory=$false)]$destinationComputerName,
        [Parameter(Mandatory=$false)][string]$testErrorMessage,
        [Parameter(Mandatory=$false)][string]$testSuccessMessage,
        [Parameter(Mandatory=$true)]$testExpectedValue,    
        [Parameter(Mandatory=$true)]$testValue,
        [Parameter(Mandatory=$false)][string]$testMessage
    )

    begin {}
    process {
        [array]$outputResult = [PSCustomObject][ordered]@{
            'Test Name' = $testName
            'Result' = $(if ($testExpectedValue -ne $testValue){"FAIL"}else{"PASS"})
            'Expected Value' = $testExpectedValue
            'Tested Value' = $testValue
            'Message' = $testMessage
            'Source Computer' = $sourceComputerName
            'Destination Computer' = $destinationComputerName
            'Test Date' = $(Get-Date)
        }
    }
    end {
        $uiHash.Status = "Completed processing result for: $testName"
        $uiHash.resultsHash += $outputResult
        return $outputResult
    }
}
