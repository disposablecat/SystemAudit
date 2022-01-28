#-----------------------------------------------------------[Functions]------------------------------------------------------------



function Get-Software{
<#
.SYNOPSIS
    Returns a list of installed software on a computer or computers
.DESCRIPTION
    Connects to remote computer's registry and iterates through Uninstall and Wow6432Node Uninstall to find installed apps. If no ComputerName
    is specified it will defautl to localhost. 
.PARAMETER ComputerName
    Specify a computer to connect to. If left out localhost will be used.
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
   Get-Software
.EXAMPLE
   Get-Software -Computername computer1
   Returns all software installed on the remote host
.EXAMPLE
   Get-Software -Computername computer1,computer2,computer3
   Returns all software installed on all hosts specified
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[System.Object]])]
    
    #Define parameters
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME

    )

    Begin
    {
        #Will execute first. Will execute one time only. Use for one time actions
        #Define base registry object
        $RegEntryBase = New-Object PSObject; 
        $RegEntryBase | Add-Member -type Noteproperty ComputerName -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty Name -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty Publisher -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty InstallDate -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty EstimatedSizeMB -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty Version -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty Wow6432Node -Value $Null;
        #Define results a generic list
        $Results = New-Object System.Collections.Generic.List[System.Object]
        $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $key64 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        
    }
    Process
    {
        #Will execute second. Will execute for each each objects piped into the function
        Try
        {
            ForEach ($Computer in $ComputerName)
            {
                
                $RegHive = [Microsoft.Win32.RegistryHive]::LocalMachine
                $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $Computer)
                $UninstallRegKey = $regKey.OpenSubKey($key)
                $UninstallRegKey.GetSubKeyNames() | %{

                    $SubKey = $UninstallRegKey.OpenSubKey($_)
                    $DisplayName = $SubKey.GetValue("DisplayName")
                    If (($DisplayName.Length -gt 0) -and ($SubKey.GetValue("IsMinorUpgrade") -eq $null) -and ($SubKey.GetValue("ReleaseType") -eq $null))
                    {
                        $RegEntry = $RegEntryBase | Select-Object *
                        $RegEntry.ComputerName = $Computer
                        $RegEntry.Name = $DisplayName.Trim() 
                        $RegEntry.Publisher = $SubKey.GetValue("Publisher")
                        $RegEntry.InstallDate = $SubKey.GetValue("InstallDate")
                        $RegEntry.Version = $SubKey.GetValue("DisplayVersion")
                        $RegEntry.EstimatedSizeMB = [Math]::Round($SubKey.GetValue("EstimatedSize")/1KB,1)
                        $RegEntry.Wow6432Node = $false
                        [void]$Results.Add($RegEntry)
                    }
    

                }
                #Check for 64-bit OS
                If ([IntPtr]::Size -eq 8)
                {
                    $UninstallRegKey64 = $regKey.OpenSubKey($key64)
                    $UninstallRegKey64.GetSubKeyNames() | %{

                        $SubKey = $UninstallRegKey64.OpenSubKey($_)
                        $DisplayName = $SubKey.GetValue("DisplayName")
                        If (($DisplayName.Length -gt 0) -and ($SubKey.GetValue("IsMinorUpgrade") -eq $null) -and ($SubKey.GetValue("ReleaseType") -eq $null))
                        {
                            $RegEntry = $RegEntryBase | Select-Object *
                            $RegEntry.ComputerName = $Computer
                            $RegEntry.Name = $DisplayName.Trim() 
                            $RegEntry.Publisher = $SubKey.GetValue("Publisher")
                            $RegEntry.InstallDate = $SubKey.GetValue("InstallDate")
                            $RegEntry.Version = $SubKey.GetValue("DisplayVersion")
                            $RegEntry.EstimatedSizeMB = [Math]::Round($SubKey.GetValue("EstimatedSize")/1KB,1)
                            $RegEntry.Wow6432Node = $true
                            [void]$Results.Add($RegEntry)
                        }
                    }
                }
            }
            return $Results
        }
        Catch
        {
            #Catch any error.
            Write-Host  “Caught an exception:” -ForegroundColor Red
            Write-Host “Exception Type: $($_.Exception.GetType().FullName)” -ForegroundColor Red
            Write-Host “Exception Message: $($_.Exception.Message)” -ForegroundColor Red
        }

    }
    End
    {
        #Will execute last. Will execute once. Good for cleanup. 
    }
}

function Get-Updates{
<#
.SYNOPSIS
    Returns a list of installed updates on a computer or computers
.DESCRIPTION
    Connects to remote computer's registry and iterates through Uninstall and Wow6432Node Uninstall to find installed apps. If no ComputerName
    is specified it will defautl to localhost.
    Numeric result codes interpreted based on following table:
    1 = No Started
    2 = In Progress
    3 = Succeeded
    4 = Succeeded with Errors
    5 = Failed

    Remote collection requires DCOM Remote Administration be open through the firewall. Default Window firewall rule "COM+ Remote Administration (DCOM-In)"
.PARAMETER ComputerName
    Specify a computer to connect to. If left out localhost will be used.
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
   Get-Updates
   Returns all updates from the localhost
.EXAMPLE
   Get-Updates -ComputerName <host>
   Returns all updates from the remote host
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[System.Object]])]
    
    #Define parameters
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = "localhost"


    )

    Begin
    {
        #Will execute first. Will execute one time only. Use for one time actions
        
    }
    Process
    {
        #Will execute second. Will execute for each each objects piped into the function
        Try
        {
            #Try this code. If something breaks ErrorActionPreference should force a terminating error and move on to catch
            ForEach ($Computer in $ComputerName)
            {
                $Output = New-Object System.Collections.Generic.List[System.Object]
                $Resultbase = New-Object PSObject; 
                $Resultbase | Add-Member -type Noteproperty ComputerName -Value $Null; 
                $Resultbase | Add-Member -type Noteproperty Date -Value $Null; 
                $Resultbase | Add-Member -type Noteproperty Title -Value $Null; 
                $Resultbase | Add-Member -type Noteproperty KB -Value $Null; 
                $Resultbase | Add-Member -type Noteproperty Description -Value $Null; 
                $Resultbase | Add-Member -type Noteproperty UpdateID -Value $Null; 
                $Resultbase | Add-Member -type Noteproperty RevisionNumber -Value $Null;
                $Resultbase | Add-Member -type Noteproperty Result -Value $Null;

                if($ComputerName -eq "localhost")
                {
                    $Session = New-Object -ComObject "Microsoft.Update.Session"
                }
                else
                {
                    $Session = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computer))
                }
                #$Session = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computer))
                $Searcher = $Session.CreateUpdateSearcher()
                $historyCount = $Searcher.GetTotalHistoryCount()
                $History = $Searcher.QueryHistory(0, $historyCount)
                foreach ($Upd in $History) 
                {
                    $Result = $Resultbase | Select-Object *
                    $Result.ComputerName = $Computer
                    $Result.Date = $Upd.Date
                    $Result.Title = $Upd.Title
                    $Result.KB = [regex]::match($Upd.Title,’KB(\d+)’)
                    $Result.Description = $Upd.Description
                    $Result.UpdateID = $Upd.UpdateIdentity.UpdateID
                    $Result.RevisionNumber = $Upd.UpdateIdentity.RevisionNumber
                    if ($Upd.ResultCode -eq 0)
                    {
                        $Result.Result = "Not Started"
                    }
                    elseif ($Upd.ResultCode -eq 1)
                    {
                        $Result.Result = "In Progress"
                    }
                    elseif ($Upd.ResultCode -eq 2)
                    {
                        $Result.Result = "Succeeded"
                    }
                    elseif ($Upd.ResultCode -eq 3)
                    {
                        $Result.Result = "Succeeded With Errors"
                    }
                    elseif ($Upd.ResultCode -eq 4)
                    {
                        $Result.Result = "Failed"
                    }
                    elseif ($Upd.ResultCode -eq 5)
                    {
                        $Result.Result = "Aborted"
                    }
                    else
                    {
                        $Result.Result = "Unknown Code"
                    }
                    $Output.Add($Result)
                }
            }
            return $OutPut
        }
        Catch
        {
            #Catch any error.
            Write-Host  “Caught an exception:” -ForegroundColor Red
            Write-Host “Exception Type: $($_.Exception.GetType().FullName)” -ForegroundColor Red
            Write-Host “Exception Message: $($_.Exception.Message)” -ForegroundColor Red
        }

    }
    End
    {
        #Will execute last. Will execute once. Good for cleanup. 
    }
}

function Get-Autoruns{
<#
.SYNOPSIS
    Returns a list of applications that are set to run automatically
.DESCRIPTION
    Returns a list of applications that are set to run automatically as pulled from various registy locations. Can be run against remote hosts.
.PARAMETER ComputerName
    Specify a computer to connect to. If left out localhost will be used.
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
   Get-Autoruns
   Returns a list of applications that are set to run on the local host.
.EXAMPLE
   Get-Software -Computername computer1
   Returns a list of applications that are set to run on the the remote host computer1
.EXAMPLE
   Get-Software -Computername computer1,computer2,computer3
   Returns a list of applications that are set to run on the the remote hosts computer1, computer2, computer3
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[System.Object]])]
    
    #Define parameters
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME

    )

    Begin
    {
        #Will execute first. Will execute one time only. Use for one time actions
        #Define base registry object
        $RegEntryBase = New-Object PSObject; 
        $RegEntryBase | Add-Member -type Noteproperty ComputerName -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty Name -Value $Null;
        $RegEntryBase | Add-Member -type Noteproperty Value -Value $Null; 
        $RegEntryBase | Add-Member -type Noteproperty RegLocation -Value $Null; 
        #Define results a generic list
        $Results = New-Object System.Collections.Generic.List[System.Object]
        $keysHKLM = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                    "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    Process
    {
        #Will execute second. Will execute for each each objects piped into the function
        Try
        {
            ForEach ($Computer in $ComputerName)
            {  
                $RegHiveHKLM = [Microsoft.Win32.RegistryHive]::LocalMachine
                $regKeyHKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHiveHKLM, $Computer)
                ForEach ($key in $keysHKLM)
                {   
                    $AutorunRegKey = $regKeyHKLM.OpenSubKey($key)
                    $AutorunRegNames = $AutorunRegKey.GetValueNames()
                    ForEach ($Name in $AutorunRegNames)
                    {
                        $RegEntry = $RegEntryBase | Select-Object *
                        $RegEntry.ComputerName = $Computer
                        $RegEntry.Name = $Name
                        $RegEntry.Value = $AutorunRegKey.GetValue($Name)
                        $RegEntry.RegLocation = $AutorunRegKey.Name
                        [void]$Results.Add($RegEntry)
                    }
                }                     
             }
            return $Results
        }
        Catch
        {
            #Catch any error.
            Write-Host  “Caught an exception:” -ForegroundColor Red
            Write-Host “Exception Type: $($_.Exception.GetType().FullName)” -ForegroundColor Red
            Write-Host “Exception Message: $($_.Exception.Message)” -ForegroundColor Red
        }

    }
    End
    {
        #Will execute last. Will execute once. Good for cleanup. 
    }
}

function Get-LinesInLargeFile{
<#
.SYNOPSIS
    Returns the number of lines in a large file or files.
.DESCRIPTION
    Provide a file or files and this will count and return the number of lines in said file. Works very well on large files where Get-Content | Measure tends to fall on its face.
.PARAMETER Files
    Parameter description
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
   Get-LinesInLargeFiles -Files "c:\temp\largefile.txt"
.EXAMPLE
   Get-LinesInLargeFiles -Files "c:\temp\largefile.txt", "c:\temp\anotherlargefile.txt"
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[System.Object]])]
    
    #Define parameters
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$Files
    )

    Begin
    {
        $FileLineCountBase = New-Object PSObject
        $FileLineCountBase | Add-Member -type NoteProperty -Name FileName -Value $null
        $FileLineCountBase | Add-Member -type NoteProperty -Name Lines -Value $null
        $Results = New-Object System.Collections.Generic.List[System.Object]
        
    }
    Process
    {
        ForEach ($File in $Files)
        {
            Try
            {
                $FullFilePath = Resolve-Path $File -ErrorAction Stop
                [int]$LinesInFile = 0
                $reader = New-Object IO.StreamReader $FullFilePath
                while($reader.ReadLine() -ne $null)
                {
                    $LinesInFile++
                }
                #Close streamreader after each file
                $reader.Close()
                $FileLineCount = $FileLineCountBase | Select *
                $FileLineCount.FileName = $FullFilePath
                $FileLineCount.Lines = $LinesInFile
                $Results.Add($FileLineCount)
            }
            Catch [System.UnauthorizedAccessException]
            {
                #Catch Access denied
                Write-Verbose "Access Denied: $File"
            }
            Catch [System.Management.Automation.ItemNotFoundException]
            {
                Write-Verbose "File not found: $File"
            }
            Catch
            {
                #Catch any other error.
                Write-Verbose “Exception Caught”
                Write-Verbose “Exception Type: $($_.Exception.GetType().FullName)”
                Write-Verbose “Exception Message: $($_.Exception.Message)”
            }
        }
        Return $Results
    }
}

function Get-EventLogStats{
<#
.SYNOPSIS
    Collects event log stats from a computer(s)
.DESCRIPTION
    Collects event log stats such as log names, log size, number of events, oldest event, newest event, and average events per second
.PARAMETER ComputerName
    Specify a computer or computers to collect stat data from
.PARAMETER EventLogName
    Specify an event log or event logs. If not specified then "Application", "Security", "System" is used.
.PARAMETER Suppress
    Supress event log permission issues and continue processing any other event logs requested that you do have access to.
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
    Get-EventLogStats
    Collects event log stats from the local computer
.EXAMPLE
    Get-EventLogStats -ComputerName server1
    Collects event log stats from the remote computer server1
.EXAMPLE
    Get-EventLogStats -ComputerName server1, server2 -EventLogName Security
    Collects Security event log stats from the remote computers server1 and server2
.EXAMPLE
    Get-EventLogStats -ComputerName server1 -EventLogName "Application", "Security", "System"
    Collects Application, Security, and System event log stats from the remote computers server1.
    Ignore event log permissions and continue regardless. For example a standard user may not have access to the Security event logs.
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[System.Object]])]
    
    #Define parameters
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$EventLogName = @("Application", "Security", "System"),

        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [switch]$Suppress
    )

    Begin
    {
        #Create Base PSObject for reuse in generic.list build
        $EventLogStatBase = New-Object PSObject; 
        $EventLogStatBase | Add-Member -type Noteproperty -Name ComputerName -Value $Null
        $EventLogStatBase | Add-Member -type Noteproperty -Name LogName -Value $Null
        $EventLogStatBase | Add-Member -type Noteproperty -Name LogSizeMB -Value $Null
        $EventLogStatBase | Add-Member -type Noteproperty -Name NumEvents -Value $Null
        $EventLogStatBase | Add-Member -type Noteproperty -Name OldestEventTime -Value $Null
        $EventLogStatBase | Add-Member -type Noteproperty -Name NewestEventTime -Value $Null
        $EventLogStatBase | Add-Member -type Noteproperty -Name AvgEPS -Value $Null
        #Generic list to return as result. More cpu/memory efficient when working with large outputs
        $Results = New-Object System.Collections.Generic.List[System.Object]
        
    }
    Process
    {
        #Will execute second. Will execute for each each objects piped into the function
        ForEach ($Computer in $ComputerName)
        {
            Try
            {
                Write-Verbose "Pinging: $Computer."
                Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop | Out-Null
                Write-Verbose "Testing connection to RPC: $Computer."
                if ($Suppress -eq $true)
                {
                    Get-WinEvent -ListLog $EventLogName -ComputerName $Computer -ErrorAction SilentlyContinue | Out-Null
                }
                else
                {
                    Get-WinEvent -ListLog $EventLogName -ComputerName $Computer -ErrorAction Stop | Out-Null
                }
                Write-Verbose "Collecting log data: $Computer."
                $EventLogs = Get-WinEvent -ListLog $EventLogName -ComputerName $Computer -ErrorAction SilentlyContinue
                ForEach ($EventLog in $EventLogs)
                {
                    Write-Verbose "Processing log: $($EventLog.LogName)"                   
                    $EventLogStat = $EventLogStatBase | Select *
                    $EventLogStat.ComputerName = $Computer
                    $EventLogStat.LogName = $EventLog.LogName
                    #Temp variable to do math before assignment. 1048576 bytes in megabyte
                    $TempLogSize = ($EventLog.FileSize / 1048576)
                    #Round variable to 1 after decimal
                    $EventLogStat.LogSizeMB = [math]::Round($TempLogSize, 1)
                    $EventLogStat.NumEvents = $EventLog.RecordCount
                    #Get Event Times
                    if($EventLog.RecordCount -eq 0)
                    {
                        Write-Verbose "Some Processing Skipped: RecordCount $($EventLog.RecordCount)"
                        $EventLogStat.OldestEventTime = $null
                        $EventLogStat.NewestEventTime = $null
                        $EventLogStat.AvgEPS = $null
                    }
                    elseif($EventLog.FileSize -eq $null)
                    {
                        Write-Verbose "Some Processing Skipped: FileSize is null"
                        $EventLogStat.OldestEventTime = $null
                        $EventLogStat.NewestEventTime = $null
                        $EventLogStat.AvgEPS = $null
                    }
                    else
                    {

                        $OldestEventTime = (Get-WinEvent -LogName $EventLog.LogName -ComputerName $Computer -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue).TimeCreated
                        $EventLogStat.OldestEventTime = $OldestEventTime
                        $NewestEventTime = (Get-WinEvent -LogName $EventLog.LogName -ComputerName $Computer -MaxEvents 1 -ErrorAction SilentlyContinue).TimeCreated
                        $EventLogStat.NewestEventTime = $NewestEventTime
                        $TotalTime = (Get-Date).Subtract($OldestEventTime).TotalSeconds
                        $TempEPS = $EventLog.RecordCount / $TotalTime
                        $EventLogStat.AvgEPS = [math]::Round($TempEPS, 5)
                    }
                    $Results.Add($EventLogStat)
                    
                }
            }
            Catch [System.Net.NetworkInformation.PingException]
            {
                Write-Verbose "Exception Caught: Cannot ping $Computer."
            }
            Catch [System.Diagnostics.Eventing.Reader.EventLogException]
            {
                Write-Verbose "Exception Caught: Could not connect to RPC service on $Computer."
            }
            Catch
            {
                #Catch any error.
                Write-Verbose “Exception Caught: $($_.Exception.Message)”
            }
            
        }
        Write-Verbose "Done."
        return $Results

    }
    End
    {
        #Will execute last. Will execute once. Good for cleanup. 
    }
}

function Get-CCMPrimaryUser{
<#
.SYNOPSIS
    Retrieve the primary users of the computer from the CCM WMI space.
.DESCRIPTION
    Retrieve the primary users of the computer from the CCM WMI space.
.PARAMETER ComputerName
    Specify a computer name or array of computer names.
.NOTES
    Version:        1.0
    Author:         disposablecat
.EXAMPLE
    Get-CCMPrimaryUser -Computername Host1
    Retrieves the primary user(s) from Host1
.EXAMPLE
    Get-CCMPrimaryUser -Computername Host1, Host2, Host3, Host4
    Retrieves the primary user(s) from Host1, Host2, Host3, Host4
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[System.Object]])]
    
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    Begin
    {
        $PrimaryUserBase = New-Object PSObject; 
        $PrimaryUserBase | Add-Member -type Noteproperty -Name ComputerName -Value $Null
        $PrimaryUserBase | Add-Member -type Noteproperty -Name User -Value $Null
        #Generic list to return as result. More cpu/memory efficient when working with large outputs
        $Results = New-Object System.Collections.Generic.List[System.Object]
    }
    Process
    {
        ForEach ($Computer in $ComputerName)
        {
            Try
            {
                Write-Verbose "Pinging: $Computer."
                Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop | Out-Null
                Write-Verbose "Testing connection to WMI: $Computer."
                $TempWMIResults = Get-WmiObject -Namespace Root\ccm\CIModels -Class CCM_PrimaryUser -ErrorAction Stop
                ForEach ($TempWMIResult in $TempWMIResults)
                {
                    $PrimaryUser = $PrimaryUserBase | Select-Object *
                    $PrimaryUser.ComputerName = $Computer
                    $PrimaryUser.User = $TempWMIResult.User
                    $Results.Add($PrimaryUser)
                }
            }
            Catch [System.Net.NetworkInformation.PingException]
            {
                Write-Verbose "Exception Caught: Cannot ping $Computer."
            }
            Catch
            {
                #Catch any error.
                Write-Verbose “Exception Caught: $($_.Exception.Message)”
            }
        return $Results
        }
    }
}