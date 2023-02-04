<#
Name: ValidateSecurityStack 2.0
Purpose: Generate Evidences for Template and Build sign-off
Author: Marc Deleplace
Creation Date: 4/11/2019
Changes: check README file.
Requirements:
1) ReportHTML Module (Install-Module -Name ReportHTML - https://www.powershellgallery.com/packages/ReportHTML/)
2) Initialize Splunk credential
    $splunkcred = Get-Credential (get username / password from Marc)
    $splunkcred.Password | ConvertFrom-SecureString | Set-Content E:\MIT-ValidateSecurityStack2.0\scriptsencrypted_password1.txt
#>

[System.Net.HttpWebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($null)

Import-Module "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTML.psm1"

# JENKINS VARIABLES #
$ComputerName = $env:hostname
$Json = $env:output_json
$Html = $env:output_html
$ShowJson = $env:showjson
$ShowHtml = $env:showhtml
$Mail = $env:mail
$To = $env:to
$Location = $env:Location

# Prompt for credentials
if ($Credential -eq $true) {
    $MyCreds = Get-Credential -Message "Please type your SA credentials (domain\username):"
    $MyCreds = New-Object System.Management.Automation.PsCredential ($MyCreds.username, $MyCreds.password)
}
else {Write-Output "Credential switch is not specified, the current user session credential ($Env:USERNAME) will be used to pull the information from $ComputerName..."}

# Reference Version for Infrastructure & InfoRisk Application stack
$CrowdStrikeRefVersion = "6.39.15314.0"
$SplunkRefVersion = "8.2.5.0"
$HiPAMRefVersion = "11.1.3"
$FlexnetRefVersion = "14.00.52"
$SCCMRefVersion = "5.00.9068.1008"
$QualysRefVersion = "4.6.1.6"

# Today's date
$Today = (Get-Date).ToString("yyyy-MM-dd")

$SplunkUser = "sys_pr_osi01"
$Encrypted = Get-Content E:\MIT-ValidateSecurityStack2.0\scriptsencrypted_password.txt | ConvertTo-SecureString
$RestCred = New-Object System.Management.Automation.PsCredential($SplunkUser, $Encrypted)

if ($Credential -eq $true) {
    $Session = New-PSSession -ComputerName $ComputerName -Credential $MyCreds
    $CimSession = New-CimSession -ComputerName $ComputerName -Credential $MyCreds
    $NTUsername = $MyCreds.UserName
}

else {
    $Session = New-PSSession -ComputerName $ComputerName
    $CimSession = New-CimSession -ComputerName $ComputerName
    $NTUsername = "$Env:USERNAME"
}

#Grab Template Information AWS, Azure, and On-Prem as required
Write-Output "Retrieving Template Information..."
if ($Location -eq "AWS") {
    Write-Output "AWS Validation Specified"
    $FlexeraLogs = "Flexera agent is NOT deployed on cloud servers"

    $AWSQuery = Invoke-Command -Session $Session -ScriptBlock {
        $MetadataUri = "http://169.254.169.254/latest/meta-data/iam/security-credentials"
        $CredentialsList = (Invoke-WebRequest -Uri $MetadataUri -UseBasicParsing).Content.Split()
        $CredentialsObject = (Invoke-WebRequest -Uri "$MetadataUri/$($CredentialsList[0])" -UseBasicParsing).Content | ConvertFrom-Json

        Set-AWSCredential -StoreAs ami_data -AccessKey $CredentialsObject.AccessKeyId -SecretKey $CredentialsObject.SecretAccessKey -SessionToken $CredentialsObject.Token

        Initialize-AWSDefaults -ProfileName ami_data -Region us-west-2
        Add-Type -Path (${env:ProgramFiles(x86)} + "\AWS SDK for .NET\bin\Net45\AWSSDK.DynamoDBv2.dll")
        $AMIID = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/ami-id -UseBasicParsing | Where-Object {$_.Content -ne $null}).content
        $ami_name = (Get-EC2Image -ImageId $AMIID -ProfileName ami_data).Name
        $ami_creation_date = (Get-EC2Image -ImageId $AMIID -ProfileName ami_data).CreationDate
        New-Object -TypeName PSCustomObject -Property @{AMI_ID = $AMIID; AMI_Name = $ami_name; AMI_Creation_Date = $ami_creation_date}
    }

    $TemplateVersionObj = [PSCustomObject]@{
        'AMI ID'            = $AWSQuery.AMI_ID
        'AMI Name'          = $AWSQuery.AMI_Name
        'AMI Creation Date' = $AWSQuery.AMI_Creation_Date
    }
}

elseif ($Location -eq "AZR") {
    Write-Output "Azure Validation Specified"
    $FlexeraLogs = "Flexera agent is NOT deployed on cloud servers"
    $AZRQuery = Invoke-Command -Session $Session -ScriptBlock {
        $meta_json = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        $image_id = ($meta_json.compute.storageProfile.imageReference.id).split('/')[-1]
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
        $SubKey = $BaseKey.OpenSubKey("SOFTWARE\\Moodys")
        $release_data = $SubKey.GetValue('AZR_Image_Name_And_Release')
        $creation_date = $SubKey.GetValue('VHD_Creation_Date')
        $TemplateInitialVersion = $SubKey.GetValue('TemplateInitialVersion')
        $VHD_ID = $image_id
        $VHD_Name = $release_data
        $VHD_Creation_Date = $creation_date

        New-Object -TypeName PSCustomObject -Property @{VHD_ID = $VHD_ID; VHD_Name = $VHD_Name; VHD_Creation_Date = $VHD_Creation_Date; TemplateInitialVersion = $TemplateInitialVersion }
    }

    $TemplateVersionObj = [PSCustomObject]@{
        'VHD ID'                 = $AZRQuery.VHD_ID
        'VHD Name'               = $AZRQuery.VHD_Name
        'VHD Creation Date'      = $AZRQuery.VHD_Creation_Date
        'TemplateInitialVersion' = $AZRQuery.TemplateInitialVersion
    }
}

else {
    Write-Output "On-Prem Validation Specified"
    # Build Flexera table (only for on-prem builds).
    Write-Output "Compiling Flexera Logs..."
    $FlexeraLogs = Invoke-Command -Session $Session -ScriptBlock {Get-EventLog -Logname ManageSoft}
    $FlexeraLogs = $FlexeraLogs | Select-Object TimeGenerated, EntryType, Source, Message

    $TemplateVersion = Invoke-Command -Session $Session -ScriptBlock {Get-ItemProperty "HKLM:\SOFTWARE\Moodys" -Name 'TemplateInitialVersion'}

    $TemplateVersionObj = [PSCustomObject]@{
        'Template Version' = $TemplateVersion.TemplateInitialVersion
        'Notes'            = $null
    }
}

# Build Table ServerInfo
Write-Output "Gathering Server Information..."
$DNSSuffixesList = Invoke-Command -Session $Session -ScriptBlock {(Get-DnsClientGlobalSetting | Select-Object @{Name = 'SuffixSearchList'; Expression = { $_.SuffixSearchList -join ', ' } }).SuffixSearchList}
$ServerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession
$ServerCores = Get-CimInstance -ClassName Win32_Processor -CimSession $CimSession | Measure-Object -Property NumberOfCores -Sum

$ServerInfoObj = [PSCustomObject]@{
    'Hostname'          = $ServerInfo.Name
    'Domain'            = $ServerInfo.Domain
    'IP Address'        = (Resolve-DNSName -Name $ComputerName -Type A).IPAddress
    'DNS Suffixes List' = $DNSSuffixesList
}

#Build Table SystemInfo
Write-Output "Gathering System Information..."
$SystemInfo = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession

$SystemInfoObj = [PSCustomObject]@{
    'System Status'       = $SystemInfo.Status
    'Operating system'    = $SystemInfo.Caption
    'System Architecture' = $SystemInfo.OSArchitecture
    'OS Version'          = $SystemInfo.Version
    'Build Number'        = $SystemInfo.BuildNumber
    'Install Date'        = $SystemInfo.InstallDate
    'Last Boot Time'      = $SystemInfo.LastBootUpTime
    'Local Time'          = $SystemInfo.LocalDateTime
}

#Build Table Server Specifications
$SpecsObj = [PSCustomObject]@{
    'Virtual'          = $ServerInfo.HypervisorPresent
    'CPUs'             = $($ServerInfo.NumberOfProcessors * $($ServerCores.Sum / $ServerCores.Count))
    'Sockets'          = $ServerInfo.NumberOfProcessors
    'Cores Per Socket' = $($ServerCores.Sum / $ServerCores.Count)
    'RAM (GB)'         = [math]::Round($($ServerInfo.TotalPhysicalMemory /1gb))
}

#Build Table Disk Information
$DiskInfo = Get-DiskSpace -ComputerName $ComputerName | Select-Object Drive, 'Size (GB)', 'FreeSpace (GB)', PercentFree
$DiskObj = @()
foreach ($DiskItem in $DiskInfo){
    $DiskObj += [PSCustomObject]@{
        'Drive'          = $DiskItem.Drive
        'Size (GB)'      = $DiskItem.'Size (GB)'
        'FreeSpace (GB)' = $DiskItem.'FreeSpace (GB)'
        'PercentFree'    = $DiskItem.PercentFree
    }
}

#Get SeInteractiveLogonRight
$RightsQuery = Invoke-Command -Session $Session -ScriptBlock {
    $RemoteOutput = @()
    if ((Test-Path C:\Temp) -eq $false) {
        New-Item -Path "C:\Temp" -ItemType Directory
    }
    $CfgFile = "c:\temp\user_rights.inf"
    secedit /export /cfg $CfgFile /areas USER_RIGHTS /quiet
    $Output = New-Object PSObject
    $Index = 0
    $Contents = Get-Content $CfgFile -Raw
    [regex]::Matches($Contents, "(?<=\[)(.*)(?=\])") | ForEach-Object {
        $Title = $_
        [regex]::Matches($Contents, "(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$Index] | ForEach-Object {
            $Section = new-object PSObject
            $_.Value -Split "\r\n" | Where-Object { $_.Length -gt 0 } | ForEach-Object {
                $Value = [regex]::Match($_, "(?<=\=).*").Value
                $Name = [regex]::Match($_, ".*(?=\=)").Value
                $Section | Add-Member -MemberType NoteProperty -Name $Name.ToString().Trim() -Value $Value.ToString().Trim() -ErrorAction SilentlyContinue | Out-Null
            }
            $Output | Add-Member -MemberType NoteProperty -Name $Title -Value $Section
        }
        $Index += 1
    }

    foreach ($ID in (($Output.'Privilege Rights'.SeInteractiveLogonRight).Split(',')).Trim("*", " ")) {
        $SID = New-Object System.Security.Principal.SecurityIdentifier($ID)
        $User = $SID.Translate([System.Security.Principal.NTAccount])

        $RemoteOutput += [PSCustomObject]@{
            Group = $User.Value
        }
    }

    Remove-Item $CfgFile -Force
    $RemoteOutput
} | Select-Object Group, @{N='ComputerName';E={$_.PSComputerName.ToUpper()}}

# Build Table Windows Services for Infra Apps & Inforisk stack
Write-Output "Collecting InfoRisk & Infrastructure Apps services information..."
$ServicesToCheck = @("CSFalconService", "SplunkForwarder", "hipamlws", "CCMExec", "ndinit", "mgssecsvc", "QualysAgent")
$ServiceCollection = Invoke-Command -Session $Session -ScriptBlock {Get-Service $Using:ServicesToCheck -ErrorAction Ignore}
$ServiceCollection = $ServiceCollection | Select-Object DisplayName, Name, Status

# Get Version Number of Products
Write-Output "Checking Versions of Infrastructure & InfoRisk Apps running..."
$ProductVersionArray = @()
$ServiceNameCollection = @("CrowdStrike Sensor", "UniversalForwarder", "Local Workstation Service", "FlexNet Inventory Agent", "Qualys")

foreach ($ServiceName in $ServiceNameCollection) {
    $ProductVersion = Get-InstalledSoftware -ComputerName $ComputerName | Where-Object Name -like "*$($ServiceName)*" | Select-Object Name, Version
    $ProductVersionArray += [PSCustomObject]@{
        Name    = $ProductVersion.Name
        Version = $ProductVersion.Version
    }
}

# Build Patching table
Write-Output "Collecting Patching related information..."
$SCCMClientVersion = Get-CimInstance -CimSession $CimSession -Namespace root\ccm -ClassName SMS_Client

if ($Credential -eq $true) {
    $LatestHotfixes = Get-HotFix -Credential $MyCreds -ComputerName $ComputerName | Select-Object HotFixID, Description, InstalledOn -Last 20 | Sort-Object InstalledOn -Descending
}
else {
    $LatestHotfixes = Get-HotFix -ComputerName $ComputerName | Select-Object HotFixID, Description, InstalledOn -Last 20 | Sort-Object InstalledOn -Descending
}

$PatchingObj = [PSCustomObject]@{
    'Name'    = "System Center Configuration Manager Agent"
    'Version' = if ($null -eq $SCCMClientVersion.ClientVersion) {
        "NOT INSTALLED"
    }

    else {
        $SCCMClientVersion.ClientVersion
    }
}

# Build Splunk table.  Only need the TLS and certificate stuff for Server 2012R2 and earlier--we'll be able to cut this out when executed on Server 2016 and later.
Add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SplunkUrl = "https://moodys.splunkcloud.com:8089/services/search/jobs/export"
$SplunkSearches = @("search index=win_allservers host=$ComputerName | sort +_time | table _time,source,host,LogName,EventCode",
    "search index=win_hitachi $ComputerName | sort -_time | table _time,index,_raw"
)

foreach ($Search in $SplunkSearches) {
    if ($Search -like "*_allservers*") {
        Write-Output "Pulling Security Logs from Splunk..."
        $SearchBody = @{
            search        = $Search
            output_mode   = "csv"
            earliest_time = "-1d@d"
            latest_time   = "-1m@m"
        }
        $OutputFile = ".\Splunk-$ComputerName-$(Get-Date -f yyyy-MM-dd).csv"
    }

    else {
        Write-Output "Pulling HiPAM logs from Splunk..."
        $SearchBody = @{
            search        = $Search
            output_mode   = "csv"
            earliest_time = "-10d@d"
            latest_time   = "-1m@m"
        }
        $OutputFile = ".\Hitachi-$ComputerName-$(Get-Date -f yyyy-MM-dd).csv"
    }

    Invoke-RestMethod -Method Get -Uri $SplunkUrl -Credential $RestCred -Body $SearchBody -OutFile $OutputFile -TimeoutSec 120
}

$SplunkLogs = Import-Csv ".\Splunk-$ComputerName-$(Get-Date -f yyyy-MM-dd).csv" -Header _time, source, host, logname, EventCode | Select-Object -Skip 1
$HitachiLogs = Import-Csv ".\Hitachi-$ComputerName-$(Get-Date -f yyyy-MM-dd).csv" -Header _time, index, _raw | Select-Object -Skip 1

# Build CrowdStrike info table
Write-Output "Gathering CrowdStrike related information..."

$VersionStr = Invoke-Command -Session $Session -ScriptBlock {
    $CrdstrikeLogPath = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
    Get-ChildItem -Path $CrdstrikeLogPath -Filter "CrowdStrike Windows Sensor_*.log"  | Sort-Object LastWriteTime | Select-String WixBundleVersion | Select-Object -First 1 | Out-String
}
$CrowdStrikeVersion = "99999999999999999"
foreach ($Log in $VersionStr) {
    $CSLogVersion = ($Log -split '=')[1].Trim()
    if ($CSLogVersion -lt $CrowdStrikeVersion) {$CrowdStrikeVersion = $CSLogVersion}
}

$CrowdStrikeConnection = Invoke-Command -Session $Session -ScriptBlock {(New-Object System.Net.Sockets.TcpClient("ts01-b.cloudsink.net", 443)).Connected}
$CSAgentID = Invoke-Command -Session $Session -ScriptBlock {(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\CSAgent\Sim").AG}
$DecimalToHex = $CSAgentID | ForEach-Object {[System.Convert]::ToString($_,16)}
$CrowdStrikeAgentID = ([string]::Join('',$DecimalToHex)).ToUpper()

$CrowdStrikeObj = [PSCustomObject]@{
    'Instantiated Version' = $CrowdStrikeVersion
    'AgentConnected'       = $CrowdStrikeConnection
    'Agent ID (AID)'       = $CrowdStrikeAgentID
}

# Build Qualys info table
Write-Output "Gathering Qualys related information..."
$QualysConnection = Invoke-Command -Session $Session -ScriptBlock {(New-Object System.Net.Sockets.TcpClient("qagpublic.qg3.apps.qualys.com", 443)).Connected}
$QualysDisplayVersion = (Get-InstalledSoftware -ComputerName $ComputerName | Where-Object Publisher -eq "Qualys, Inc.").Version

$QualysObj = [PSCustomObject]@{
    'QualysAgent Version'   = if ($null -eq $QualysDisplayVersion) {
        "Verify Qualys Agent is Running/Installed"
    }
    else {$QualysDisplayVersion}
    'Qualys Public Endpoint Reachable' = $QualysConnection
}

# Build the AutoCheck (QA) Tab/Table
Write-Output "Starting Automated QA Process..."

# Checking Status of the infrastructure and inforisk applications services...
$QASvcErr = 0
if ($ServiceCollection.Name -notcontains "QualysAgent") {$QASvcErr = $QASvcErr + 1}
if ($ServiceCollection.Name -notcontains "SplunkForwarder") {$QASvcErr = $QASvcErr + 1}
if ($ServiceCollection.Name -notcontains "CSFalconService") {$QASvcErr = $QASvcErr + 1}
foreach ($QAsvcrecord in $ServiceCollection.Status) {
    if ($QAsvcrecord -ne "Running") {$QASvcErr = $QASvcErr + 1}
}
if ($QASvcErr -eq "0") {$QAServiceOutput = "Success"}
else {$QAServiceOutput = "Failure"}

# Checking Versions of the infrastructure and inforisk applications...
$ProductVersionArrayVerErr = 0
if ($QAServiceOutput -eq "Failure") {$ProductVersionArrayVerErr = $ProductVersionArrayVerErr + 1}
$ProductVersionArray += $PatchingObj
foreach ($Product in $ProductVersionArray) {
    switch ($($Product).Name) {
        "System Center Configuration Manager Agent" {$AppVersion = $SCCMRefVersion}
        CSFalconService {$AppVersion = $CrowdStrikeRefVersion}
        hipamlws        {$AppVersion = $HiPAMRefVersion}
        mgssecsvc       {$AppVersion = $FlexnetRefVersion}
        ndinit          {$AppVersion = $FlexnetRefVersion}
        QualysAgent     {$AppVersion = $QualysRefVersion}
        SplunkForwarder {$AppVersion = $SplunkRefVersion}
    }

    if ([version]($Product).Version -lt [version]$AppVersion) {$ProductVersionArrayVerErr = $ProductVersionArrayVerErr + 1}
}

if ($ProductVersionArrayVerErr -eq 0) {$QAAppVerOutput = "Success"}
else {$QAAppVerOutput = "Failure"}

# Checking Latest Hotfixes deployed (SCCM)... if latest patch older than 30 days, then it failed (Microsoft KB deployment being scheduled every month)
$DateLatestInstPatch = $LatestHotfixes.InstalledOn[0]
$DateLatestInstPatch = $DateLatestInstPatch.ToString("yyyy-MM-dd")
$SCCMPatchTimeSpan = (New-TimeSpan -Start $DateLatestInstPatch -End $Today).Days
$QASCCMErr = 0
if ($SCCMPatchTimeSpan -gt "30") {$QASCCMErr = $QASCCMErr + 1}
if ($QASCCMErr -eq "0") {$QASCCMOutput = "Success"}
else {$QASCCMOutput = "Failure"}

# Checking Hipam logs...
$QAHipamErr = 0
if (!$HitachiLogs) {$QAHipamErr = $QAHipamErr + 1}
if ($QAHipamErr -eq "0") {$QAHipamOutput = "Success"}
if ($HitachiLogs -match "Discovered system is now successfully managed") {$QAHipamOutput = "Success"}
elseif ($HitachiLogs -match "Password changed successfully") {$QAHipamOutput = "Success"}
else {$QAHipamOutput = "Failure"}

# Checking SeInteractiveLogonRight...
if ($RightsQuery.Group -contains "BUILTIN\Administrators" -and $RightsQuery.Group -contains "BUILTIN\Users" -and $RightsQuery.Group -contains "BUILTIN\Backup Operators" ) {$QALogonRightOutput = "Success"}
else {$QALogonRightOutput = "Failure"}

# Checking Splunk logs...
$QASplunkErr = 0
if (!$SplunkLogs) {$QASplunkErr = $QASplunkErr + 1}
if ($QASplunkErr -eq "0") {$QASplunkOutput = "Success"}
else {$QASplunkOutput = "Failure"}

# Checking Crowdstike Falcon agent connection to the CrowdStrike public endpoint...
$QACrdStrikeConnectErr = 0
if ($CrowdStrikeConnection -ne "True") {$QACrdStrikeConnectErr = $QACrdStrikeConnectErr + 1}
if ($QACrdStrikeConnectErr -eq "0") {$QACrdStikeConnectOutput = "Success"}
else {$QACrdStikeConnectOutput = "Failure"}

# Checking if Qualys can connect to public endpoint
if ($QualysConnection -eq $true) {$QAQualysConnection = "Success"}
else {$QAQualysConnection = "Failure"}

# Comparing the current version running of CrowdStrike against the approved version ... (Info)
if ($ProductVersionArray.Version[0] -ge $CrowdStrikeRefVersion) {$QACrdStrikeInstVerOutput = "Success"}
elseif ($ProductVersionArray.Version[0] -eq $CrowdStrikeRefVersion) {$QACrdStrikeInstVerOutput = "Success"}
else {$QACrdStrikeInstVerOutput = "Failure"}

# Comparing CrowdStrike instantiated version against the approved version... (Info)
if ($CrowdStrikeVersion -lt $CrowdStrikeRefVersion) {$QACrdStrikeInstVerOutput2 = "Failure"}
else {$QACrdStrikeInstVerOutput2 = "Success"}

# Flexera logs
$QAFlexErr = 0
if (!$FlexeraLogs) {$QAFlexErr = $QAFlexErr + 1}
if ($Location -ne "ONPREM") {$QAFlexErr = "N/A. Flexera is not deployed to Cloud instances."}
elseif ($QAFlexErr -eq "0") {$QAFlexErr = "Success"}
else {$QAFlexErr = "Failure"}

# Building the array of all automated QA outputs run above
$AutoQAObj = [PSCustomObject]@{
    'Infrastructure and Inforisk Applications are all running?'                                     = $QAServiceOutput
    'Infrastructure and Inforisk Applications are all running the approved version or higher?'      = $QAAppVerOutput
    'The latest KBs have been deployed (less than 30 days)?'                                        = $QASCCMOutput
    'The server is showing up in the HiPAM logs and client is configured successfully?'             = $QAHipamOutput
    'The server is forwarding Windows Security Logs to Splunk?'                                     = $QASplunkOutput
    'The necessary user groups are granted the SeInteractiveLogonRight?'                            = $QALogonRightOutput
    'The Server can connect to CrowdStrike Falcon agent Public Endpoint'                            = $QACrdStikeConnectOutput
    'The CrowdStrike Version Instantiated is running same or higher version than the approved one?' = $QACrdStrikeInstVerOutput2
    'The Current Version of CrowdStrike is running same or higher version than the approved one?'   = $QACrdStrikeInstVerOutput
    'The Flexera agent is running and generating logs?'                                             = $QAFlexErr
    'The Server can connect to the Qualys public endpoint'                                          = $QAQualysConnection
}

# START Building the report
$WebServer = "http://ftc-wbitsbld701/reports/"

#Company logo that will be displayed on the left, can be URL or UNC. This one is base64 encoded for portability.
$CompanyLogo = @"
data:image/jpeg;base64,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 /vfAD77wh0/84hv/+MhPvvKXz/zmO1/zIQAAOw=="
"@

#Logo that will be on the right side, can be URL or UNC. This one is base64 encoded for portability.
$RightLogo = @"
data:image/jpeg;base64,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 LTA0OjAwyLyvXQAAAABJRU5ErkJggg=="
"@

$ReportSavePath = "E:\MIT-ValidateSecurityStack2.0\reports"
$ReportName = "$($Today)_$($ComputerName)_QA"

if (!$SplunkLogs) {$SplunkLogs = [PSCustomObject]@{'Error' = "No Logs!"}}
if (!$HitachiLogs) {$HitachiLogs = [PSCustomObject]@{'Error' = "No Logs!"}}
if (!$FlexeraLogs) {$FlexeraLogs = [PSCustomObject]@{'Error' = "No Logs!"}}

# JSON Output
if ($Json -eq $true) {
    Write-Output "Creating the JSON Report output, please wait..."

    $HitachiLogs = $HitachiLogs | Select-String -Pattern Password
    $SplunkLogs = $SplunkLogs | Select-Object -First 10

    $JsonOutput = [PSCustomObject]@{
        "Template Information"                                   = $TemplateVersionObj
        "Server Information"                                     = $ServerInfoObj
        "SystemInformation"                                      = $SystemInfoObj
        "Service Status"                                         = $ServiceCollection
        "CIT Agents Version"                                     = $ProductVersionArray
        "CrowdStrike"                                            = $CrowdStrikeObj
        "Qualys"                                                 = $QualysObj
        "SCCM Latest KBs"                                        = $LatestHotfixes
        "HiPAM (Hitachi logs pulled from Splunk)"                = $HitachiLogs
        "Centralized Logging (Security logs pulled from Splunk)" = $SplunkLogs
        "Flexera Logs"                                           = $FlexeraLogs
        "Automated QA"                                           = $AutoQAObj
    }

    $JsonOutput | ConvertTo-Json | Out-File "$ReportSavePath\$ReportName.json"
    Write-Output "JSON Report $($ReportName).json has been successfully created!"

    if ($ShowJson -eq $true) {$JsonOutput}
}

# HTML Output
if ($Html -eq $true) {
    Write-Output "Creating the HTML Report output, please wait..."
    $TabArray = @('Dashboard', 'SCCM', 'HiPAM', 'CrowdStrike', 'Splunk', 'Flexera', 'Qualys')

    $Rpt = New-Object 'System.Collections.Generic.List[System.Object]'
    $Rpt += Get-HtmlOpenPage -TitleText 'Operating System Template | Passport Check' -LeftLogoString $CompanyLogo -RightLogoString $RightLogo -CSSPath "E:\MIT-ValidateSecurityStack2.0\reports\css" -CSSName ServerValidationReport
    $Rpt += Get-HtmlTabHeader -TabNames $TabArray
    $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[0] -TabHeading "Generated by: $($NTUsername)"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "General Information"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Template Information"
    $Rpt += Get-HtmlContentTable $TemplateVersionObj
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Server Information"
    $Rpt += Get-HtmlContentTable $ServerInfoObj
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "System Information"
    $Rpt += Get-HtmlContentTable $SystemInfoObj -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "System Specifications"
    $Rpt += Get-HtmlContentTable $SpecsObj -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Disk Information"
    $Rpt += Get-HtmlContentTable $DiskObj -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Group(s) Allowed Interactive Login (SeInteractiveLogonRight)"
    $Rpt += Get-HtmlContentTable $RightsQuery
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "InfoRisk and Infrastructure Applications Stack | Service Status"
    $Rpt += Get-HtmlContentTable $ServiceCollection -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Automated QA"
    $Rpt += Get-HtmlContentTable $AutoQAObj
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlTabContentClose
    $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[1] -TabHeading "Generated by: $($NTUsername)"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "SCCM Client Details"
    $Rpt += Get-HtmlContentTable $PatchingObj -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Latest Microsoft KBs Successfully Deployed"
    $Rpt += Get-HtmlContentDataTable $LatestHotfixes
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlTabContentClose
    $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[2]  -TabHeading "Generated by: $($NTUsername)"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "HiPAM Client Details"
    $Rpt += Get-HtmlContentTable $ProductVersionArray[2] -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "HiPAM Check-in"
    $Rpt += Get-HtmlContentDataTable $HitachiLogs -HideFooter  -ErrorAction SilentlyContinue
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlTabContentClose
    $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[3] -TabHeading "Generated by: $($NTUsername)"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "CrowdStrike Client Details"
    $Rpt += Get-HtmlContentTable $ProductVersionArray[0] -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "CrowdStrike Agent Connection to the Endpoint"
    $Rpt += Get-HtmlContentTable $CrowdStrikeObj -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlTabContentClose
    $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[4] -TabHeading "Generated by: $($NTUsername)"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Splunk Client Details"
    $Rpt += Get-HtmlContentTable $ProductVersionArray[1] -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Splunk Information"
    $Rpt += Get-HtmlContentDataTable $SplunkLogs
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlTabContentClose
    $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[6] -TabHeading "Generated by: $($NTUsername)"
    $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Qualys Client Details"
    $Rpt += Get-HtmlContentTable $QualysObj -HideFooter
    $Rpt += Get-HtmlContentClose
    $Rpt += Get-HtmlTabContentClose

    if ($Location -eq "ONPREM") {
        Write-Output "On-Prem specified. Creating Flexera tab."
        $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[5] -TabHeading "Generated by: $($NTUsername)"
        $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Flexera Client Details"
        $Rpt += Get-HtmlContentTable $ProductVersionArray[3] -HideFooter
        $Rpt += Get-HtmlContentClose
        $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "Flexera Logs"
        $Rpt += Get-HtmlContentDataTable $FlexeraLogs
        $Rpt += Get-HtmlContentClose
        $Rpt += Get-HtmlTabContentClose
    }

    else {
        Write-Output "Cloud Specified. Annotating Flexera not required.."
        $Rpt += Get-HtmlTabContentOpen -TabName $TabArray[5] -TabHeading "Generated by: $($NTUsername)"
        $Rpt += Get-HtmlContentOpen -BackgroundShade 1 -HeaderText "$($FlexeraLogs)"
        $Rpt += Get-HtmlContentClose
        $Rpt += Get-HtmlTabContentClose
    }

    $Rpt += Get-HtmlClosePage

    if ($ShowHtml) {Save-HTMLReport -ReportContent $Rpt -ReportName $ReportName -ReportPath $ReportSavePath -ShowReport}
    else {Save-HTMLReport -ReportContent $Rpt -ReportName $ReportName -ReportPath $ReportSavePath}

    Write-Output "HTML Report $ReportName.html has been successfully created! $WebServer$ReportName.html"
    Copy-Item -Path $ReportSavePath\$ReportName.html -Destination E:\MIT-ValidateSecurityStack2.0\reports\JenkinsUpload\Validation.html
}

if ($Mail -eq $true) {
    # Create attachment
    if ($Json -eq $true) {$OutputFile = "$($ReportSavePath)\$($ReportName).json"}
    if ($Html -eq $true) {$OutputFile = "$($ReportSavePath)\$($ReportName).html"}
    Compress-Archive -Path $OutputFile -DestinationPath "C:\TEMP\$ComputerName.zip" -Force
    $Attachment = "C:\TEMP\$ComputerName.zip"

    # Sendmail
    if (!$From) {$From = "ValidateSecurityStack2.0@moodys.com"}
    if (!$To) {$To = "snowdev@moodys.com, snowtest@moodys.com, snowstg@moodys.com"}
    if (!$Subject) {$Subject = "$($Today): ValidateSecurityStack2.0 | $ComputerName"}
    if (!$Body) {[string]$Body = "Please find Validation Report attached for: $($ComputerName)"}
    if (!$SMTP) {$SMTP = "mailrelay.nslb.ad.moodys.net"}
    Write-Output "Sending E-mail to: $($To)"
    Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -Attachments $Attachment -SmtpServer $SMTP

    # Cleaning attachment
    Remove-Item -Path $Attachment -Force
}

Remove-PSSession $Session -ErrorAction Ignore
Remove-CimSession $CimSession -ErrorAction Ignore

Write-Output "***Process is complete***"

if ($AutoQAObj -contains 'Failure') {
    Write-Error "Validation Failures Detected"
    exit 5
}
