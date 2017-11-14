clear
Start-Sleep -s 5

#Set Some vairables that we need later
$ProcCount = -1
$MatchCount = -1
$ErrorCountProcess = -1
$Date = Get-Date -Format g
$CommandLineEvents = @()
$FullPathArray = @()
$EventsID1 = @()

#######################[Change this stuff]######################################
$DirectoryOfModules = "C:\Users\bsidestovictim\Desktop\Tool\Modules"
$ReportFile = "C:\Users\bsidestovictim\Desktop\Tool\Report\Report.txt"
Import-Module 'C:\Program Files\WindowsPowerShell\Modules\Get-InjectedThread.ps1'
Import-Module 'C:\Program Files\WindowsPowerShell\Modules\Get-WinEventData.ps1'
################################################################################

#Clear the contents of the old report file
Clear-Content $ReportFile

#Add the Report Headers
$ReportDataHeaders = "Report for: " + $env:computername + " Date: " + $Date
Add-Content $ReportFile $ReportDataHeaders; Add-Content $ReportFile `n

Start-Sleep -s 2

#Injected thread stuff here
Clear-Variable -Name *Injected*

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Getting Injected Threads..."
$InjectedThreads = Get-InjectedThread -ErrorAction SilentlyContinue
Add-Content $ReportFile "[Injected Thread Data]"; Add-Content $ReportFile `n
$InjctedThreadsType = $InjectedThreads.GetType()
if ($InjctedThreadsType.BaseType.Name -eq 'System.Array'){
    foreach($Thread in $InjectedThreads){
        $ProcCount ++ | Out-Null
        $InjectedThreadReportData = "Injected Process Name: " + $InjectedThreads.ProcessName[$ProcCount] + " Command Line: " + $InjectedThreads.CommandLine[$ProcCount]
        Add-Content $ReportFile $InjectedThreadReportData; Add-Content $ReportFile `n
    }
}
else{
        #Write-Host "Only One Injected Thread"
        $InjectedThreadReportDataSingle = "Injected Process Name: " + $InjectedThreads.ProcessName + " Command Line: " + $InjectedThreads.CommandLine
        Add-Content $ReportFile $InjectedThreadReportDataSingle; Add-Content $ReportFile `n
}

Start-Sleep -s 1

#Look at parent child relationships here... 

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking at Parent/Child Process Relationships..."
Add-Content $ReportFile "[Suspect Parent/Child Relationships] "; Add-Content $ReportFile `n
$Processes = Get-WmiObject win32_process | select ProcessName, ParentProcessId, Name, ExecutablePath
foreach($Process in $Processes){
    #[Add more stuff here later] - this is telling us that something spawned cmd.exe - this should usually be explorer.exe only (someone has a shell open)
    if($Process.Name -eq "cmd.exe"){
        $ParentProcessName = Get-Process -id $Process.ParentProcessId -ErrorAction SilentlyContinue
        $ParentChildReport = $ParentProcessName.Name + " Spawned " + $Process.ProcessName
        if($ParentProcessName.ProcessName -ne "explorer"){
            Add-Content $ReportFile $ParentChildReport
        }
    }   
}

Start-Sleep -s 1

#Looking for some sketchy command line arguments here

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking at process executions..."
Add-Content $ReportFile `n; Add-Content $ReportFile "[Interesting Process Command Line Data]"; Add-Content $ReportFile `n


$EventsID1 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=1} | Get-WinEventData | select *

foreach ($Event1Loop1 in $EventsID1)
{
    if(($Event1Loop1.EventDataCommandLine -like '*wscript*') -or ($Event1Loop1.e_CommandLine -like '*cscript*') -or ($Event1Loop1.e_CommandLine -like '*MSBuild*')){
        $CommandLineEvents += $Event1Loop1.e_CurrentDirectory.Trim() + $Event1Loop1.e_CommandLine.Trim() 
        foreach($CommandLineEvent in $CommandLineEvents){
            $FileNameMatch = $Event1Loop1.e_CommandLine -match '\s(.*)'
            if ($FileNameMatch){
                $FileName = $Matches[1]
                $FullPaths = $Event1Loop1.e_CurrentDirectory + $FileName; $FullPaths | Out-Null
                $FullPathArray += $FullPaths.Replace(' ','')
                $CommandLines = $Event1Loop1.e_CommandLine
                Add-Content $ReportFile $CommandLines
            }
        }
    }
}

Start-Sleep -s 1

#Signature Stuff Here

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking for Authenticode Signature Mismatches..."
$Signatures = @()
$Signature = @()
foreach ($Event1Loop2 in $EventsID1){
    $Signatures = Get-AuthenticodeSignature -FilePath $Event1Loop2.e_Image -ErrorAction SilentlyContinue
     
    foreach($Signature in $Signatures){    
        if($Signature.Status -like "HashMisMatch"){
            Write-Host -BackgroundColor Red "Hash Mismatch Found, Check Report"
            Add-Content $ReportFile `n; Add-Content $ReportFile "[Hash Mismatch Details]"; Add-Content $ReportFile `n
            $SignatureReport = "Image: " + $Event1Loop2.e_Image + " Status: " + $Signature.Status + " OSBinary: " + $Signature.IsOSBinary + " Signer: " + $Signature.SignerCertificate.Issuer
            Add-Content $ReportFile $SignatureReport
        }    
    }
}

Start-Sleep -s 1

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking for encoded PowerShell..."
foreach ($Event1Loop3 in $EventsID1){
    
    #Sketchy PowerShell Loop here
    if(($Event1Loop3.e_CommandLine -like '*-EncodedCommand*') -or ($Event1Loop3.e_CommandLine -like '*-encodedcommand*') ){

        Write-Host -BackgroundColor Red "Found suspicious command line arguments, check report"
        Add-Content $ReportFile `n; Add-Content $ReportFile "[Suspicious PowerShell Command Lines]"; Add-Content $ReportFile `n
        Add-Content $ReportFile $Event1Loop3.e_CommandLine
        $DecodedCommandLine = $Event1Loop3.e_CommandLine -match ('\-EncodedCommand(.*)')
        $DecodedCommandLine = $Matches[0].Replace("-EncodedCommand","")
        $DecodedCommandLine = $DecodedCommandLine -replace '["]',''
        $DecodedCommandLine = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($DecodedCommandLine))
        Add-Content $ReportFile `n; Add-Content $ReportFile "[Decoded Command Line]"; Add-Content $ReportFile `n
        Add-Content $ReportFile $DecodedCommandLine.ToLower()

    }
}

Start-Sleep -s 1

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Grabbing contents of files found in command line arguments..."
#Get the contents of the command line files here
Add-Content $ReportFile `n; Add-Content $ReportFile "[Command line argument file contents]"; Add-Content $ReportFile `n
foreach($FullPathEntry in $FullPathArray){
    $FileContents2 = Get-Content $FullPathEntry -Head 30 -ErrorAction SilentlyContinue
    $FileConentsHeader = "Contents of: " + $FullPathEntry  
    if([string]::IsNullOrEmpty($FileContents2)){
        #Empty file contents, do nothing
    }
    else
    {
        Add-Content $ReportFile $FileConentsHeader
        $FileContentsData = $FileContents2 | Out-String
        Add-Content $ReportFile $FileContentsData
    }
}

Start-Sleep -s 1

#Credential Stuff Here

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking at processes that accessed LSASS..."

Add-Content $ReportFile `n
Add-Content $ReportFile "[Credential Watch]"; Add-Content $ReportFile `n

$EventsID10 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=10} | Get-WinEventData | select *

foreach($Event10 in $EventsID10){
    $CredReport = "LSASS Access by: " + $Event10.e_SourceImage + " Granted Access: " + $Event10.e_GrantedAccess 
    Add-Content $ReportFile $CredReport
}

Start-Sleep -s 1

#Umanaged PowerShell Here
Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking for unmanaged PowerShell..."
$EventsID7 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=7} | Get-WinEventData | select *
Add-Content $ReportFile `n; Add-Content $ReportFile "[UnManaged PowerShell Detections]"; Add-Content $ReportFile `n
foreach($Event7 in $EventsID7){
    $EventID7ReportData = "Executable: " + $Event7.e_Image + " Image Loaded: " + $Event7.e_ImageLoaded + " " + $Event7.e_DataHashes + " Signed: " + $Event7.e_Signed
    Add-Content $ReportFile $EventID7ReportData
}

Start-Sleep -s 1

#Registry AutoRuns Here:

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking at Registry for Autoruns..."
$EventsID13 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=13} | Get-WinEventData | select *

Add-Content $ReportFile `n; Add-Content $ReportFile "[New Run Keys]"; Add-Content $ReportFile `n

foreach($Event13 in $EventsID13){
    if($Event13.e_TargetObject.ToString() -like '*CurrentVersion\Run*'){
        $ReportRegistryData = $Event13.e_TargetObject.ToString() + "(" + $Event13.e_Details + ")"
        Add-Content $ReportFile $ReportRegistryData
    }
}

Start-Sleep -s 1

#WMI Stuff
Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Checking for WMI persistence..."
Add-Content $ReportFile `n; Add-Content $ReportFile "[WMI Filter Activity]"; Add-Content $ReportFile `n
$EventsID19 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=19} | Get-WinEventData | select *
foreach($Event19 in $EventsID19){
    $WMIReport19 = $Event19.e_Name + $Event19.e_Query
    Add-Content $ReportFile $WMIReport19
}

Add-Content $ReportFile `n; Add-Content $ReportFile "[WMI Event Consumer Activity]"; Add-Content $ReportFile `n
$EventsID20 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=20} | Get-WinEventData | select *
foreach($Event20 in $EventsID20){
    $WMIReport20 = $Event20.e_Name + $Event20.e_Destination
    Add-Content $ReportFile $WMIReport20
}

Add-Content $ReportFile `n; Add-Content $ReportFile "[WMI Event Consumer to Filter Activity]"; Add-Content $ReportFile `n
$EventsID21 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=21} | Get-WinEventData | select *
foreach($Event21 in $EventsID21){
    $WMIReport21 = $Event21.e_Consumer + $Event21.e_Filter
    Add-Content $ReportFile $WMIReport21
}

Start-Sleep -s 1

#Network Connections of Process
Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Looking at process network connectivity..."

Add-Content $ReportFile `n; Add-Content $ReportFile "[Process Network Connectivity]"; Add-Content $ReportFile `n
$EventsID3 = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=3} | Get-WinEventData | select *
$IPConnectionData = $EventsID3 | Group-Object -Property e_Image,e_DestinationIP | sort -Property count -Descending | Select-Object count,name
$IPConnectionDataForReport = $IPConnectionData | Out-String
Add-Content $ReportFile $IPConnectionDataForReport

Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "Generating the report...should be done soon"