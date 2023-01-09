Set-Variable -Name AdoptiumAPI -Option Constant -Value 'https://api.adoptium.net'


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
        $proc = Start-Process -Verb RunAs -PassThru -FilePath 'msiexec' -ArgumentList "/x$AppGUID", '/norestart', '/qn'
        $proc.WaitForExit()
        return $proc.ExitCode
    }
    finally {
        if ($proc) {
            # Note: Needs to be disposed even if process ran to completion.
            $proc.Dispose()
        }
    }
}

$InstalledSoftware = $null
function Get-JavaInstallations {
    # Since enumerating every installed application is somewhat expensive, we want to avoid calls to 'Get-InstalledSoftware' as much as possible
    if (-not $InstalledSoftware) {
        $InstalledSoftware = Get-InstalledSoftware
    }

    $oracle = $InstalledSoftware | Where-Object { $_.AppVendor -and $_.AppVendor.Contains('Oracle') -and $_.InstallLocation -and $_.AppName -and $_.AppName.Contains('Java') }
    $openjdks = $InstalledSoftware | Where-Object { $_.AppVendor -and ($_.AppVendor.Contains('Amazon') -or $_.AppVendor.Contains('Eclipse')) -and $_.AppName -and ($_.AppName.Contains('Temurin') -or $_.AppName.Contains('Corretto')) }

    return $oracle, $openjdks
}

function Get-TemurinInstaller {
    Param(
        [string] $Flavor = 'jdk',
        [parameter(Mandatory = $true)]
        [int] $FeatureVersion,
        [parameter(Mandatory = $true)]
        [string] $TmpDir
    )

    $url = "${AdoptiumAPI}/v3/installer/latest/${FeatureVersion}/ga/windows/x64/${Flavor}/hotspot/normal/eclipse"
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
        $m = & $Exe -version 2>&1 | Select-Object -First 1 | Select-String -Pattern '([0-9]+[.]){2,}[^"]+'
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

    $components = $FullVersion.Split('.')
    if ([int]($components[0]) -eq 1) { # Java 8 or older
        $components[1]
    } else {
        $components[0]
    }
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

    if (-not $userVars.ContainsKey('JAVA_HOME') -and -not $systemVars.ContainsKey('JAVA_HOME')) {
        $rv | Add-Member -MemberType NoteProperty -Name VariableStore -Value $null
        $rv | Add-Member -MemberType NoteProperty -Name Value -Value $null
    }

    $rv
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

function Test-IsOpenJDK {
    Param(
        [string] $Exe
    )
    if ([System.IO.File]::Exists($Exe) -or $(Test-CommandOnPath $Exe)) {
        & $Exe -version 2>&1 | Select-String -SimpleMatch 'OpenJDK' -Quiet
    }
    else {
        throw "$Exe does not seem to exist!"
    }
}

function Test-Elevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsInLocalAdmins {
    whoami /groups | Select-String -SimpleMatch 'S-1-5-32-544' -Quiet
}

function Write-Title {
    Param(
        [string] $Message
    )

    Write-Host -ForegroundColor Cyan "<< $Message >>"
    Write-Host ''
}

function Write-Subtitle {
    Param(
        [string] $Title,
        [string] $Message
    )

    Write-Host -NoNewline "${Title}: "
    Write-Host -ForegroundColor DarkGray $Message
}

function Receive-Answer {
    Param(
        [string] $Question
    )

    $answer = $null
    while (-not $answer) {
        $answer = Read-Host -Prompt "${Question} [y/n]"
        if ($answer.ToLowerInvariant() -ne 'y' -and $answer.ToLowerInvariant() -ne 'n') {
            Write-Host -ForegroundColor DarkGray "Please just answer with either 'y' or 'n'."
            $answer = $null
        } else {
            return $answer -eq 'y'
        }
    }

}

function _dealWithJDKs {
     # JDKs
     Write-Title 'Java Development Kits (JDKs)'
     Write-Subtitle 'OpenJDK' 'Looking for OpenJDK installations on the system.'
 
     Write-Subtitle 'Oracle JDKs' 'Looking for Oracle JDK installations on the system.'
}

function _dealWithJRE {
    # JRE
    Write-Title 'Java Runtime Environment (JRE)'
    Write-Subtitle 'Oracle JRE' 'Looking for an installation of Oracle JRE on the system.'
}

#region pre-checks
function _precheckConnectivity {
    Write-Subtitle 'Connectivity' "Trying to reach the Adoptium API at ${AdoptiumAPI}"
    if (Test-CanConnect) {
        Write-Host -ForegroundColor Green "Excellent! Adoptium API is responding!`r`n"
    } else {
        Write-Host -ForegroundColor Red 'Failed to connect!'
        Write-Host ''
        Write-Host -ForegroundColor Yellow @"
Trying to connect to ${AdoptiumAPI} resulted in an error. This script requires an active Internet connection to proceed.
Please verify that your machine is connected to the Internet and that ${AdoptiumAPI} can be reached.
"@
        Write-Host ''
        Write-Host 'Exiting now!'
        exit
    }
}

function _precheckShellElevation {
    Write-Subtitle 'Admin Rights' 'Checking if we are running in an elevated shell.'
    if (Test-Elevated) {
        Write-Host -ForegroundColor Green "Swell! It looks like we are running in an elevated command prompt!`r`n"
    } elseif (Test-IsInLocalAdmins) {
        Write-Host -ForegroundColor DarkGreen @"
Great! It looks like your account is a local admin. It is possible that you will see a bunch of UAC prompts along the way.
If you don't feel like clicking, consider re-running this script in an elevated PowerShell prompt.

"@
    } else {
        Write-Host -ForegroundColor Yellow @"
Warning! Could not determine if your account has local admin rights. It is possible that you do if e.g. your account
inherits the right indirectly via AD group membership. However determining this is beyond the capabilities of this
little script.

To make everything crystal clear, it is recommended to stop now and re-run the script in an elevated PowerShell prompt.

"@
        if (Receive-Answer 'Do you want to stop now?') {
            Write-Host 'Okay. See you later!'
            exit
        } else {
            Write-Host "Fine. We'll continue. But if I fail it is on you!`r`n"
        }
    }
}

function _precheckDefaultJava {
    Write-Subtitle 'Default Installation' 'Looking for a default Java installation and checking JAVA_HOME.'

    $ver = Get-JavaVersion 'java.exe'
    if ($ver -ne '0.0.0') {
        $featureVer = Get-JavaFeatureVersion $ver
        Write-Host "‣ It looks like at least one version of Java is installed: $(if (Test-IsOpenJDK 'java.exe ') { 'OpenJDK' } else { 'Oracle' }) Java ${featureVer} ($ver)"
    } else {
        Write-Host "‣ Could not find a default Java installation."
    }

    $jhome = Get-JavaHomeVar
    if ($jhome.VariableStore) {
        Write-Host "‣ It looks like the environment variable JAVA_HOME is set and it is pointing to $($jhome.Value)"
    } else {
        Write-Host '‣ It seems that the environment variable JAVA_HOME is not set.'
    }

    Write-Host ''
}

function _prechecks {
    Write-Title 'Initial Checks'
    _precheckDefaultJava
    _precheckShellElevation
    _precheckConnectivity
}

function Test-CanConnect {
    curl.exe -s -I -o $null -f $AdoptiumAPI
    return $?
}
#endregion


try {
    $tdir = New-TempDir
    _prechecks
    _dealWithJRE
    _dealWithJDKs
}
finally {
    Write-Host 'Cleaning up!'
    if ($tdir) {
        Remove-Item -Recurse -Force $tdir
    }
}



#$tdir = New-TempDir
#$msi = Get-TemurinInstaller -FeatureVersion 11 -TmpDir $tdir
#Install-Temurin -MsiInstaller $msi

# Get-JavaVersion 'java.exe' | Get-JavaFeatureVersion
#$installs = Get-InstalledSoftware | Where-Object { $_.AppVendor -and $_.AppVendor.StartsWith('Oracle') -and $_.InstallLocation }
#foreach ($install in $installs) {
#    $path = "$($install.InstallLocation)bin\java.exe"
#    Write-Host "Path is: $path"
#    Write-Host "Is JDK? $($install | Test-IsJDK)"
#    Write-Host "Full version is $(Get-JavaVersion $path)"
#    Write-Host "Feature version is $(Get-JavaVersion $path | Get-JavaFeatureVersion)"
#    if (Test-IsJDK $install.InstallLocation) {
#        $comp = "$($install.InstallLocation)bin\javac.exe"
#        Write-Host "Compiler version is $(Get-JavaVersion $comp)"
#    }
#}

# $prop, $open = Get-JavaInstallations

# foreach ($install in $prop) {
#     $path = "$($install.InstallLocation)bin\java.exe"
#     Write-Host "Oracle Java"
#     Write-Host "Path is: $path"
#     Write-Host "Is JDK? $($install | Test-IsJDK)"
#     Write-Host "Full version is $(Get-JavaVersion $path)"
#     Write-Host "Feature version is $(Get-JavaVersion $path | Get-JavaFeatureVersion)"
#     if (Test-IsJDK $install.InstallLocation) {
#         $comp = "$($install.InstallLocation)bin\javac.exe"
#         Write-Host "Compiler version is $(Get-JavaVersion $comp)"
#     }
# }

# foreach ($install in $open) {
#     if ($install.InstallLocation) {
#         # Anoyingly, Corretto doesn't register the install location.
#         $path = "$($install.InstallLocation)bin\java.exe"
#         Write-Host "OpenJDK Java"
#         Write-Host "Path is: $path"
#         Write-Host "Is JDK? $($install | Test-IsJDK)"
#         Write-Host "Full version is $(Get-JavaVersion $path)"
#         Write-Host "Feature version is $(Get-JavaVersion $path | Get-JavaFeatureVersion)"
#         if (Test-IsJDK $install.InstallLocation) {
#             $comp = "$($install.InstallLocation)bin\javac.exe"
#             Write-Host "Compiler version is $(Get-JavaVersion $comp)"
#         }   
#     } else {
#         Write-Host "Amazon Corretto"
#         Write-Host "Path is not known..."
#         Write-Host "Is JDK? Likely..."
#         Write-Host "Full version is $($install.AppVersion)"
#         Write-Host "Feature version is $($install.AppVersion | Get-JavaFeatureVersion)"
#     }
# }


