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
    $T = "$($Env:Temp)\o2t.$([convert]::ToString((Get-Random -Maximum 0x7FFFFFFF),16).PadLeft(8,'0')).tmp"
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
                        $AppInstallLocation = $($AppDetails.GetValue("InstallLocation"))
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
                        $OutputObj | Add-Member -MemberType NoteProperty -Name InstallLocation -Value $AppInstallLocation
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

function Uninstall-InstalledSoftware2 {
    Param (            
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ComputerName = $env:computername,
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [string]$AppGUID
    )            

    try {
        $proc = Start-Process -Verb RunAs -PassThru -FilePath 'msiexec' -ArgumentList "/x$AppGUID", '/norestart', '/qn'
        $proc.WaitForExit()
        return $proc.ExitCode
    }
    catch {
        write-error "Failed to trigger uninstall. Exiting."
        $_
        exit
    }
    finally {
        if ($proc) {
            # Note: Needs to be disposed even if process ran to completion.
            $proc.Dispose()
        }
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
    }
    else {
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

function Get-JavaVersion {
    Param(
        [string] $Exe
    )
    if ([System.IO.File]::Exists($Exe) -or $(Test-CommandOnPath $Exe)) {
        $m = & $Exe -version 2>&1 | Select-Object -First 1 | Select-String -Pattern '([0-9][.]){2,}[^"]+'
        $m.Matches.Value
    }
    else {
        '0.0.0'
    }
}

function Get-JavaFeatureVersion {
    Param(
        [parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string] $FullVersion
    )

    $FullVersion.Split('.')[1]
}

function Get-JavaHomeVar {
    # .NET calls them 'Machine' vars, but in the UI they are typically referred to as 'System variables'
    $systemVars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine)
    $userVars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::User)

    $rv = New-Object -TypeName PSobject

    if ($systemVars.ContainsKey('JAVA_HOME')) {
        $rv | Add-Member -MemberType NoteProperty -Name VariableStore -Value 'System'
        $rv | Add-Member -MemberType NoteProperty -Name Value -Value $systemVars['JAVA_HOME']
    }

    if ($userVars.ContainsKey('JAVA_HOME')) {
        $rv | Add-Member -MemberType NoteProperty -Name VariableStore -Value 'User'
        $rv | Add-Member -MemberType NoteProperty -Name Value -Value $userVars['JAVA_HOME']
    }
}

function Test-DefaultIsJRE {
    # It is actually a bit tricky to figure out if the default version is a JDK or the JRE
    # because newer versions of Java deliver shim binaries similar to the ones found on macOS.
    # Thus, we need to resort to a bit of a heuristic.
    $hasCompiler = Test-CommandOnPath 'javac.exe'
    $hasRuntime = Test-CommandOnPath 'java.exe'

    if ($hasRuntime -and $hasCompiler) {
        # Not quite done yet...
        $runtimeVersion = Get-JavaVersion
        $compilerVersion = '0.0.0' # TODO

        if ($compilerVersion -eq $runtimeVersion) {
            # If compiler version matches runtime version, our best guess is that the default
            # is pointing to the JDK, but of course, this is still not 100% guaranteed.
            return $false
        }
        else {
            # If however the compiler version is in fact different, then we assume that the
            # default Java is the JRE.
            return $true
        }
    }
    elseif ($hasRuntime -and -not $hasCompiler) {
        return $true # -> very likely it is just the JRE
    }
    else {
        throw 'Java compiler but no runtime found!' # This is weird.
    }
}

function Test-IsJDK {
    Param(
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [string] $InstallLocation
    )

    $compiler = "${InstallLocation}bin\javac.exe"
    $runtime = "${InstallLocation}bin\java.exe"

    [System.IO.File]::Exists($compiler) -and [System.IO.File]::Exists($runtime)
}

function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#$tdir = New-TempDir
#$msi = Get-TemurinInstaller -FeatureVersion 11 -TmpDir $tdir
#Install-Temurin -MsiInstaller $msi

# Get-JavaVersion 'java.exe' | Get-JavaFeatureVersion
$installs = Get-InstalledSoftware | Where-Object { $_.AppVendor -and $_.AppVendor.StartsWith('Oracle') -and $_.InstallLocation }
foreach ($install in $installs) {
    $path = "$($install.InstallLocation)bin\java.exe"
    Write-Host "Path is: $path"
    Write-Host "Is JDK? $($install | Test-IsJDK)"
    Write-Host "Full version is $(Get-JavaVersion $path)"
    Write-Host "Major version is $(Get-JavaVersion $path | Get-JavaFeatureVersion)"
}

Get-JavaVersion 'java.exe'
