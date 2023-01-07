function Test-CommandOnPath {
    Param ($command)
    $currentPref = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {
        if (Get-Command $command) {
            return $true
        }
    }
    catch {
        return $false
    }
    finally {
        $ErrorActionPreference = $currentPref
    }
}

function New-TempDir {
    # Make a new folder based upon a TempFileName
    $T="$($Env:Temp)\o2t.$([convert]::ToString((Get-Random -Maximum 0x7FFFFFFF),16).PadLeft(8,'0')).tmp"
    New-Item -ItemType Directory -Path $T
}

function Get-InstalledSoftware {
    [cmdletbinding()]
    Param(            
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]            
        [string[]]$ComputerName = $env:computername            
    )

    Begin {            
        $UninstallRegKeys = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",            
            "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")            
    }

    Process {
        foreach ($Computer in $ComputerName) {                        
            if (Test-Connection -ComputerName $Computer -Count 1 -ea 0) {            
                foreach ($UninstallRegKey in $UninstallRegKeys) {            
                    try {            
                        $HKLM = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine', $computer)            
                        $UninstallRef = $HKLM.OpenSubKey($UninstallRegKey)            
                        $Applications = $UninstallRef.GetSubKeyNames()            
                    }
                    catch {            
                        Write-Verbose "Failed to read $UninstallRegKey"            
                        Continue            
                    }            
            
                    foreach ($App in $Applications) {            
                        $AppRegistryKey = $UninstallRegKey + "\\" + $App            
                        $AppDetails = $HKLM.OpenSubKey($AppRegistryKey)            
                        $AppGUID = $App            
                        $AppDisplayName = $($AppDetails.GetValue("DisplayName"))            
                        $AppVersion = $($AppDetails.GetValue("DisplayVersion"))            
                        $AppPublisher = $($AppDetails.GetValue("Publisher"))            
                        $AppInstalledDate = $($AppDetails.GetValue("InstallDate"))            
                        $AppUninstall = $($AppDetails.GetValue("UninstallString"))            
                        if ($UninstallRegKey -match "Wow6432Node") {            
                            $Softwarearchitecture = "x86"            
                        }
                        else {            
                            $Softwarearchitecture = "x64"            
                        }            
                        if (!$AppDisplayName) { continue }            
                        $OutputObj = New-Object -TypeName PSobject             
                        $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name AppName -Value $AppDisplayName            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name AppVersion -Value $AppVersion            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name AppVendor -Value $AppPublisher            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name InstalledDate -Value $AppInstalledDate            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name UninstallKey -Value $AppUninstall            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name AppGUID -Value $AppGUID            
                        $OutputObj | Add-Member -MemberType NoteProperty -Name SoftwareArchitecture -Value $Softwarearchitecture            
                        $OutputObj            
                    }            
                }             
            }            
        }
    }
}

function Uninstall-InstalledSoftware {
    Param (            
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ComputerName = $env:computername,
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [string]$AppGUID
    )            

    try {
        $returnval = ([WMICLASS]"\\$computerName\ROOT\CIMV2:win32_process").Create("msiexec `/x$AppGUID `/norestart `/qn")
    }
    catch {
        write-error "Failed to trigger the uninstallation. Review the error message"
        $_
        exit
    }
    switch ($($returnval.returnvalue)) {
        0 { "Uninstallation command triggered successfully" }
        2 { "You don't have sufficient permissions to trigger the command on $Computer" }
        3 { "You don't have sufficient permissions to trigger the command on $Computer" }
        8 { "An unknown error has occurred" }
        9 { "Path Not Found" }
        9 { "Invalid Parameter" }
    }
}

function Get-TemurinInstaller {
    Param(
        [string] $Flavor = 'jdk',
        [parameter(Mandatory = $true)]
        [int] $FeatureVersion,
        [parameter(Mandatory = $true)]
        [string] $TmpDir
    )

    $url = "https://api.adoptium.net/v3/installer/latest/${FeatureVersion}/ga/windows/x64/${Flavor}/hotspot/normal/eclipse"
    $fileName = "temurin-${Flavor}-${FeatureVersion}.msi"
    $outFile = [System.IO.Path]::Combine($TmpDir, $fileName)
    
    $status = curl.exe -s -w '%{http_code}' $url

    if ($status -eq 307) {
        curl.exe -# -L -o $outFile $url
    } else {
        throw "Failed to download Temurin installer!"
    }

    $outFile
}

function Install-Temurin {
    Param(
        [parameter(Mandatory = $true)]
        [string] $MsiInstaller
    )

    Start-Process -Wait -FilePath $MsiInstaller -ArgumentList "/quiet"
}

$tdir = New-TempDir
$msi = Get-TemurinInstaller -FeatureVersion 11 -TmpDir $tdir
Install-Temurin -MsiInstaller $msi


