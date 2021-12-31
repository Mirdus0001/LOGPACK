# =====================================================================================
# === logpack v.10 ===
# ==================
# The script is saving various PC logs and information for troubleshooting purposes
# M. Smejkal 12/2021 CEE PwC IT Endpoint Team (miroslav.smejkal@pwc.com)
# =====================================================================================

Cls
Write-Host ------------------'"LOGPACK" is starting...' --------------------------------
Start-Sleep -Seconds 2

$compName = hostname 
$mainpath = 'C:\Users\Public\Desktop\PC_Logs\'
$ZIPpath = 'C:\Users\Public\Desktop\'
$FileDate = (Get-Date (Get-Date ).AddMinutes(+2) -format "dd-MM-yyyy-HH-mm-ss")
$zipFname = 'PC_logs_' + $compName + '_' + $ENV:Username + '.zip'
 




 #######################
### F U N C T I O N S ###
 #######################



        ##File cleanup / make the folder
        Function CleanMakeFldr
        {
            if (Test-Path $mainpath) {
                Remove-Item $mainpath -Recurse
            }
            if (Test-Path $ZIPpath$zipFname) {
                Remove-Item $ZIPpath$zipFname -Recurse
            }
            New-Item -Path $mainpath -ItemType Directory | Out-Null
            New-Item -Path $mainpath\DeliveryOptimisation -ItemType Directory | Out-Null
            Write-Host - Cleanup
        }






        ## Delivery Optimisation logs
        Function DelOptim
        {
            Get-DeliveryOptimizationStatus > $mainpath\DeliveryOptimisation\do_Status.log
            Get-DeliveryOptimizationPerfSnap > $mainpath\DeliveryOptimisation\do_PerfSnahp.log
            Get-DeliveryOptimizationPerfSnapThisMonth > $mainpath\DeliveryOptimisation\do_PerfSnapTHISMONTH.log
            Get-NetTCPConnection -LocalPort 7680 -Verbose > $mainpath\DeliveryOptimisation\do_NetTCPConnection_Port7680.log | Out-Null
            Get-DeliveryOptimizationLog | export-csv -notypeinformation -delimiter ',' -path $mainpath\DeliveryOptimisation\do_Log.csv
            Write-Host - Delivery Optimisation logs
        }





        ## Compress main folder
        Function Compress
        {
            Write-Host Compressing output file...
            Compress-Archive -Path $mainpath\* -DestinationPath $ZIPpath$zipFname -CompressionLevel Optimal | Out-Null
            Start-Sleep -Seconds 2
            if (Test-Path $mainpath) 
                {
                    Remove-Item $mainpath -Recurse
                }
            Write-Host 
            Write-Host ----------------------------------------------------------------------
            Write-Host - Script has finished. File containing logs created -> $ZIPpath$zipFname
            cd 'C:\Users\Public\Desktop'

        }   





        ## List installed MS updates as in Control Panel - Updates History
        Function MSupdsHistory
            {
            $wu = new-object -com 'Microsoft.Update.Searcher'
            $totalupdates = $wu.GetTotalHistoryCount()
            $all = $wu.QueryHistory(0,$totalupdates)    
            $OutputCollection=  @()
            Foreach ($update in $all)
                {
                $string = $update.title
                $Regex = 'KB\d*'
                $KB = $string | Select-String -Pattern $regex | Select-Object { $_.Matches }
                    $output = New-Object -TypeName PSobject
                    $output | add-member NoteProperty 'HotFixID' -value $KB.' $_.Matches '.Value
                    $output | add-member NoteProperty 'Title' -value $string
                    $OutputCollection += $output
                }
            $OutputCollection | Sort-Object HotFixID | Format-Table -AutoSize > $mainpath\_WUpdates-history.log
            Write-Host - MS updates history
            }






            ## Creates WindowsUpdate.log file
            Function WinUpdLogNative
        {
            function Out-Default {} #this is to hide stupid powershell hardcoded output for this particular command
            Out-Default
                Get-WindowsUpdateLog -LogPath $mainpath\WindowsUpdate.log | Out-Null
            Remove-Item -Path function:Out-Default
                # make finishing time of the script
                    $FinishTime = (Get-Date (Get-Date ).AddSeconds(+150) -format "dd/MM/yyyy HH:mm")

                cls
                Write-Host '-------------Continuing the "LOGPACK" script --- it will finish approximately at'$FinishTime
                Write-Host - Cleanup
                Write-Host - Native WindowsUpdate.log file
        }






        ## Takes all Airwatch (Intelligent Hub) related information
        Function AirWatch
            {
                New-Item -Path $mainpath\AirWatchProgDataLogs -ItemType Directory | Out-Null
                if (Test-Path 'C:\ProgramData\Airwatch\UnifiedAgent\Logs') {
                    Copy-Item 'C:\ProgramData\Airwatch\UnifiedAgent\Logs\*' -Destination $mainpath\AirWatchProgDataLogs -Recurse | Out-Null
                }
                Write-Host '- AirWatch (Intelligent HUB) logs'       
            }






            ## Takes full computer info
        Function FullCompInfo
        {
            Get-ComputerInfo > $mainpath\_Comp_Info.txt
            # msinfo32 /nfo $mainpath\_Comp_Summary_msinfo32.nfo /categories +systemsummary | Out-Null 
            Write-Host '- Computer info'
        } 






        ## Takes all drivers info
        Function AllDriversInfo 
        {
            Get-WindowsDriver -Online -All |  Out-File -FilePath $mainpath\Drivers_info.txt
            Write-Host '- Drivers info'
        }

        `




        ## Takes network info
        Function NetwInfo 
        {
            ipconfig /all | Out-File -FilePath $mainpath\_Ipconfig-all.txt
            Write-Host '- Network info'
        }






        ## Exports various registry keys important in troubleshooting
        Function Registry
        {

            $RegPath01 = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
            $RegPath02 = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy'
            $RegPath03 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            $RegPath04 = 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent'
            $RegPath05 = 'HKLM:\SOFTWARE\WOW6432Node\PwC'

            # --- Delivery Optimisation
            # ---------------------------------------------------------------------------
            Get-ChildItem $RegPath01 -Recurse |
                Where-Object {$_.Name -like "*Delivery*"}|
                Format-Table -AutoSize > $mainpath\DeliveryOptimisation\do_Reg_hklm_SW_MS_PolMgr_current_device.txt
                Write-Host '- HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'

            # --- Win Updates Policy
            # ---------------------------------------------------------------------------
            Get-ChildItem $RegPath02 -Recurse |
                Where-Object {$_.Name -like "*PolicyState*"} |
                Format-Table -AutoSize > $mainpath\hklm_SW_MS_WU_WinUpd_PolicyState.txt
                Write-Host '- HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy'
            
            # --- Unistall
            # ---------------------------------------------------------------------------   
            $ErrorActionPreference = "SilentlyContinue"
                Get-ChildItem $RegPath03 -Recurse |
                    Format-Table -AutoSize > $mainpath\hklm_UNISTALL_SW_MS_Win_CurrVer_UNINST.txt
                    # export-csv -notypeinformation -delimiter ',' -path $mainpath\hklm_SW_MS_Win_CurrVer_UNISTALL_.csv
            $ErrorActionPreference = 'Continue'
                Write-Host '- HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

            # --- Intelligent Hub - what was installed per machine and users
            # ---------------------------------------------------------------------------
            Get-ChildItem $RegPath04 -Recurse |
                Where-Object {$_.Name -like "*S-1*"} |
                Format-Table -AutoSize > $mainpath\hklm_SW_AirWatch_AppDeplAgent.txt
                Write-Host '- HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent'  
            
            # --- WOW6432Node\PwC - WUDU, Restart Utility, Current Build, Software
            # ---------------------------------------------------------------------------
            Get-ChildItem $RegPath05 -Recurse |
                Where-Object {$_.Name -like "*PwC*"} |
                Format-Table -AutoSize > $mainpath\hklm_WOW6432Node_SW_BUILDINFO_Sensors.txt
                Write-Host '- HKLM:\SOFTWARE\WOW6432Node\PwC -> OS build and W1 sensors info'  

            # Write-Host '- Registry content written'
            
        }







        ## Event-log - Copying evtx files - System, Application, Setup, 
        Function Event-Log
        {
            New-Item -Path $mainpath\EventLogs -ItemType Directory | Out-Null
            Copy-Item 'c:\WINDOWS\System32\winevt\Logs\System.evtx' -Destination $mainpath\EventLogs -Recurse | Out-Null
            Copy-Item 'c:\WINDOWS\System32\winevt\Logs\Application.evtx' -Destination $mainpath\EventLogs -Recurse | Out-Null
            Copy-Item 'c:\WINDOWS\System32\winevt\Logs\Setup.evtx' -Destination $mainpath\EventLogs -Recurse | Out-Null
            Write-Host '- Windows Event Log files'
        }







        ## Global and CEE software distribution packages' logs - WUDU logs, etc.
        Function C_Win_Log_SW
        {
            New-Item -Path $mainpath\C_Win_Log_SW -ItemType Directory | Out-Null
            if (Test-Path 'C:\Windows\Logs\Software') {
                Copy-Item 'C:\Windows\Logs\Software\*' -Destination $mainpath\C_Win_Log_SW -Recurse | Out-Null
            }
            Write-Host '- C:\Windows\Logs\Software\*.*'
        }





        ## Info about services
        Function ServicesInfo
        {
            Get-Service |
            Select Name,CanPauseAndContinue,CanShutdown,CanStop,DisplayName,ServiceName,Status,StartType |
            export-csv -notypeinformation -delimiter ',' -path $mainpath\_Services.csv
            Write-Host '- Services'
        }






        ## Info about processes
        Function ProcessInfo
        {
            $properties=@(
                @{Name="Process Name"; Expression = {$_.name}},
                @{Name="CPU (%)"; Expression = {[Math]::Round(($_.PercentProcessorTime / (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors),1)}},    
                @{Name="Memory (MB)"; Expression = {[Math]::Round(($_.workingSetPrivate / 1mb),2)}}
            )

            Get-WmiObject -class Win32_PerfFormattedData_PerfProc_Process | 
                Select-Object $properties | Sort-Object "Process Name" > $mainpath\_Processes_CPU_RAM.txt
                # export-csv -notypeinformation -delimiter ',' -path $mainpath\Processes_CPU_RAM.csv
                
            Get-Process |
                Select PriorityClass, Path, FileVersion, ProductVersion, Company, Description, StartTime |
                # Format-Table * > $mainpath\processes_DETAIL.txt
                export-csv -notypeinformation -delimiter ',' -path $mainpath\Processes_DETAIL.csv

            Write-Host '- Processes'
        }





        # gets what time and date formats masks are set, fist day of a week, month names, UI language etc...
        Function CultureAndFormats
        {
            Get-Culture >> $mainpath\Time_Culture_Date_formats.txt
            (Get-Culture).Calendar >> $mainpath\Time_Culture_Date_formats.txt
            (Get-Culture).DateTimeFormat >> $mainpath\Time_Culture_Date_formats.txt
            Write-Host '- Culture, date and time formats, etc...'

        }






        # get info which time zone is set
        Function Timezone
        {
            Get-TimeZone > $mainpath\Time_zone.txt
            Write-Host '- Time Zone'
        }






        # makes file name showing when the script finished collecting logs
        Function ThisRuntm
        {
            "" > $mainpath\__Done_at__$FileDate
        }





        # gets list of oppened apps windows
        Function OpenedApps
        {
            Get-Process | Select MainWindowTitle,ProcessName,Id | where{$_.MainWindowTitle -ne ""} > $mainpath\_Opened_applications.txt
            Write-Host '- Opened applications'
        }






        # gets list of interactive users
        Function LoggedOnUsrs
        {
            Get-Process -IncludeUserName |
                Select-Object UserName,SessionId |
                    Where-Object { $_.UserName -ne $null } |
                        Sort-Object SessionId -Unique > $mainpath\_Logged-In_Users.txt
            Write-Host '- Get active interactively logged on user(s)'
        }
        




        # lists apps registered in Add Remove programs - both 32 and 64 bit
        Function InstalledApps
        {
            Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                Select DisplayName, DisplayVersion |
                 where-object {$_.DisplayName -ne $null} |
                    export-csv -notypeinformation -delimiter ',' -path $mainpath\_InstalledApps_raw.csv

            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                Select DisplayName, DisplayVersion |
                 where-object {$_.DisplayName -ne $null} |
                    export-csv -notypeinformation -delimiter ',' -path $mainpath\_InstalledApps_raw.csv -Append
            
            # sorrting, removing duplicities
            Import-Csv $mainpath\_InstalledApps_raw.csv | sort DisplayName -Unique | Export-Csv -Path $mainpath\_InstalledApps.csv -NoTypeInformation
            if (Test-Path $mainpath\_InstalledApps_raw.csv) 
                {
                Remove-Item $mainpath\_InstalledApps_raw.csv
                }
            
            Write-Host '- Add/Remmove registered installed apps.'
        }





        # NetStat output - opened ports
        Function NetStat
        {
            Get-NetTCPConnection | sort State > $mainpath\_NetStat_opened_ports.txt
            Write-Host '- NetStat (Get-NetTCPConnection) - opened ports'
        }





        ## BSOD mini dumps
        Function BSOD
        {
            New-Item -Path $mainpath\Minidump -ItemType Directory | Out-Null
            if (Test-Path 'C:\Windows\Minidump\') {
                Copy-Item 'C:\Windows\Minidump\\*' -Destination $mainpath\Minidump -Recurse | Out-Null
            }
            Write-Host '- C:\Windows\Minidump\*.*'
        }



        ## Windows Features
        Function WinFeatures
        {
            Get-WindowsOptionalFeature -Online | Sort-Object State, FeatureName | Format-Table -AutoSize > $mainpath\WindowsFeatures.txt
            Write-Host '- Windows Features'
        }



        ## Windows Capabilities
        Function WinCapabilities
        {
            Get-WindowsCapability -Online | Sort-Object State, Name | Format-Table -AutoSize > $mainpath\WindowsCapabilities.txt
            Write-Host '- Windows Capabilities'       
        }

        ## Print drivers
        Function PrintDrvs
        {
            Get-WmiObject -class Win32_PrinterDriver |
             Select __RELPATH,__PATH,ConfigFile,DataFile,MonitorName,Name,OEMUrl,SupportedPlatform,Version |
              export-csv -notypeinformation -delimiter ',' -path $mainpath\PrintersDrivers_info.csv
            Write-Host '- Printer Drivers'
        }
        


 ################################
### F U N C T I O N S    E N D ###
 ################################





CleanMakeFldr
WinUpdLogNative
MSupdsHistory
DelOptim
Event-Log
AirWatch
FullCompInfo
AllDriversInfo
NetwInfo
ServicesInfo
ProcessInfo
WinFeatures
WinCapabilities
PrintDrvs
Registry
C_Win_Log_SW
CultureAndFormats
Timezone
OpenedApps
ThisRuntm
LoggedOnUsrs
InstalledApps
NetStat
BSOD
Compress





#=========================================================================================================================================#
###### TO DO ####
###### -   DONE - Windows Features list
###### -   DONE - Windows Capabilitiess list
###### -   DONE - Print drivers info
###### -   DONE - Speed it up - "Unistall" regkey export redone
###### - improve/unify the code
###### - GetAppxPackage ---- Get-AppxPackage | Sort-Object Name | Export-Csv -NoTypeInformation -Delimiter ";" -Path 'C:\users\public\Downloads\appxPKGS.csv' ----
###### - export list of lnk shortcuts
###### - in export to csv replace coma by ; as it then opens directly as a table in Excel