#region global vars
Set-Variable -Name AdoptiumAPI -Option Constant -Value 'https://api.adoptium.net'
# temporary download directory where .msi files are stored (cf. New-TempDir, Get-TemurinInstaller)
$global:DownloadDir

# hashtables holding information about discovered Java installations (full and feature version, architecture, JDK or JRE etc.)
# ...for the default java.exe (first one on the PATH if any)
$global:DefaultJavaFacts = $null
# ...for the default javac.exe (first one on the PATH if any JDK)
$global:DefaultJavaCompilerFacts = $null
# ...for the installation referenced by JAVA_HOME in the user store
$global:UserJavaHomeFacts = $null
# ...for the installation referenced by JAVA_HOME in the system store
$global:SystemJavaHomeFacts = $null

# flag indicating if this script got restarted in an elevated (admin) shell
$global:Elevated = $false

# List of paths to Java installations that got removed/uninstalled
$global:RemovedJavaHomes = @()

# list of installed msis fetched from the registry (cf. Get-JavaInstallations)
# ... at the beginning of script execution
$global:InstalledSoftware

# ... and at the end of script execution (filtered by OpenJDK installations)
$global:NewInstalls = $null
#endregion

#region general helper methods
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

function Get-Arch {
    [CmdletBinding(DefaultParameterSetName = "None")]
    PARAM(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $Path
    )
    
    BEGIN {
        # PE Header machine offset
        [int32]$MACHINE_OFFSET = 4
        # PE Header pointer offset
        [int32]$PE_POINTER_OFFSET = 60
        # Initial byte array size
        [int32]$PE_HEADER_SIZE = 4096
    }
    
    PROCESS {
        # Create a location to place the byte data
        [byte[]]$BYTE_ARRAY = New-Object -TypeName System.Byte[] -ArgumentList @(, $PE_HEADER_SIZE)
        # Open the file for read access
        try {
            $FileStream = New-Object -TypeName System.IO.FileStream -ArgumentList ($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            # Read the requested byte length into the byte array
            $FileStream.Read($BYTE_ARRAY, 0, $BYTE_ARRAY.Length) | Out-Null
        }
        finally {
            $FileStream.Close()
            $FileStream.Dispose()
        }
        #
        [int32]$PE_HEADER_ADDR = [System.BitConverter]::ToInt32($BYTE_ARRAY, $PE_POINTER_OFFSET)
        try {
            [int32]$machineUint = [System.BitConverter]::ToUInt16($BYTE_ARRAY, $PE_HEADER_ADDR + $MACHINE_OFFSET)
        }
        catch {
            $machineUint = 0xffff
        }
        switch ($machineUint) {
            0x0000 { return 'UNKNOWN' }
            0x0184 { return 'ALPHA' }
            0x01d3 { return 'AM33' }
            0x8664 { return 'AMD64' }
            0x01c0 { return 'ARM' }
            0x01c4 { return 'ARMNT' } # aka ARMV7
            0xaa64 { return 'ARM64' } # aka ARMV8
            0x0ebc { return 'EBC' }
            0x014c { return 'I386' }
            0x014d { return 'I860' }
            0x0200 { return 'IA64' }
            0x0268 { return 'M68K' }
            0x9041 { return 'M32R' }
            0x0266 { return 'MIPS16' }
            0x0366 { return 'MIPSFPU' }
            0x0466 { return 'MIPSFPU16' }
            0x01f0 { return 'POWERPC' }
            0x01f1 { return 'POWERPCFP' }
            0x01f2 { return 'POWERPCBE' }
            0x0162 { return 'R3000' }
            0x0166 { return 'R4000' }
            0x0168 { return 'R10000' }
            0x01a2 { return 'SH3' }
            0x01a3 { return 'SH3DSP' }
            0x01a6 { return 'SH4' }
            0x01a8 { return 'SH5' }
            0x0520 { return 'TRICORE' }
            0x01c2 { return 'THUMB' }
            0x0169 { return 'WCEMIPSV2' }
            0x0284 { return 'ALPHA64' }
            0xffff { return 'INVALID' }
        }
    }
}

function Get-Bitness {
    Param(
        [parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Exe
    )

    $arch = Get-Arch $Exe
    if ($arch -eq 'I386') {
        return 32
    }
    elseif ($arch -eq 'AMD64') {
        return 64
    }
    else {
        throw "Unsupported architecture: ${arch}"
    }
}

function New-TempDir {
    # Make a new folder based upon a TempFileName
    $T = "$($Env:Temp)\o2t.$([convert]::ToString((Get-Random -Maximum 0x7FFFFFFF),16).PadLeft(8,'0')).tmp"
    New-Item -ItemType Directory -Path $T
}

function Get-InstalledSoftware {

    Begin {            
        $UninstallRegKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',            
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
        $currentPref = $ErrorActionPreference
        $ErrorActionPreference = 'stop'
    }

    Process {
                   
        foreach ($UninstallRegKey in $UninstallRegKeys) {        
            try {            
                $UninstallRef = Get-Item -Path $UninstallRegKey
                $Applications = $UninstallRef.GetSubKeyNames()            
            }
            catch {            
                Write-Verbose "Failed to read $UninstallRegKey"            
                Continue            
            }            
            
            foreach ($App in $Applications) {            
                $AppRegistryKey = $UninstallRegKey + "\" + $App            
                $AppDetails = Get-Item -Path $AppRegistryKey
                $AppGUID = $App            
                $AppDisplayName = $($AppDetails.GetValue("DisplayName"))            
                $AppVersion = $($AppDetails.GetValue("DisplayVersion"))            
                $AppPublisher = $($AppDetails.GetValue("Publisher"))
                # Special treatment for Amazon Corretto
                if ($AppDisplayName -and $AppDisplayName.Contains('Corretto')) {
                    $subkey = if ($AppDisplayName.Contains('JRE')) { 'Java Runtime Environment' } else { 'Java Development Kit' }
                    $ver = $AppVersion.Split('.')
                    $verMod = "$($ver[0]).$($ver[1]).$($ver[2])_$($ver[3])"
                    $jsoftPath = "HKLM:\SOFTWARE\JavaSoft\${subkey}\${verMod}"
                    try {
                        $key = Get-Item -Path $jsoftPath
                        $AppInstallLocation = $key.GetValue('JavaHome')
                    }
                    catch {
                        $AppInstallLocation = $($AppDetails.GetValue("InstallLocation"))
                    } # Well, it was worth a shot
                            
                }
                else {
                    $AppInstallLocation = $($AppDetails.GetValue("InstallLocation"))
                }
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

    End {
        $ErrorActionPreference = $currentPref
    }
}

function Uninstall-InstalledSoftware {
    Param (
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [string]$AppGUID
    )            

    try {
        $proc = Start-Process -Verb RunAs -PassThru -FilePath 'msiexec' -ArgumentList "/x$AppGUID", '/quiet', '/norestart', '/qn'
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
#endregion

#region permission helpers
function Test-Elevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsInLocalAdmins {
    whoami /groups | Select-String -SimpleMatch 'S-1-5-32-544' -Quiet
}

function Restart-HostElevated {
    $proc = Get-Process -Id $PID
    $ep = Get-ExecutionPolicy
    $psExeArgs = @( '-ExecutionPolicy'; $ep; '-File'; "`"${PSCommandPath}`"")
    $params = @{ FilePath = $proc.Path; Verb = 'RunAs'; ArgumentList = $psExeArgs }

    Write-Host 'Waiting for admin shell to exit...'
    Start-Process -Wait @params
    _postRefreshPath
    exit
}
#endregion

#region Java helpers
function Get-JavaInstallations {
    param([switch] $Refresh)
    # Since enumerating every installed application is somewhat expensive, we want to avoid calls to 'Get-InstalledSoftware' as much as possible
    if (-not $global:InstalledSoftware -or $Refresh) {
        $global:InstalledSoftware = Get-InstalledSoftware
    }

    $oracle = $global:InstalledSoftware | Where-Object { $_.AppVendor -and $_.AppVendor.Contains('Oracle') -and $_.InstallLocation -and $_.AppName -and $_.AppName.Contains('Java') }
    $openjdks = $global:InstalledSoftware | Where-Object { $_.AppVendor -and ($_.AppVendor.Contains('Amazon') -or $_.AppVendor.Contains('Eclipse')) -and $_.AppName -and ($_.AppName.Contains('Temurin') -or $_.AppName.Contains('Corretto')) }

    if (-not $oracle) {
        $oracle = @()
    }

    if (-not $openjdks) {
        $openjdks = @()
    }
    return $oracle, $openjdks
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
    if ([int]($components[0]) -eq 1) {
        # Java 8 or older
        [int]($components[1])
    }
    else {
        [int]($components[0])
    }
}

function Get-JavaUpdateVersion {
    Param(
        [string] $FullVersion
    )

    # only a thing for Java 8
    if ($FullVersion.StartsWith('1.') -and $FullVersion.Contains('_')) {
        [int] $FullVersion.Split('_')[1]
    }
    else {
        0
    }
}

function Test-IsNewLic {
    Param(
        [string] $FullVersion
    )

    $featureVersion = Get-JavaFeatureVersion $FullVersion

    if ($featureVersion -eq 8) {
        $update = Get-JavaUpdateVersion $FullVersion
        return $update -gt 202
    }
    elseif ($featureVersion -lt 8) {
        return $false
    }

    return $true
}

function Get-JavaVendor {
    Param(
        [string] $Exe
    )
    if ([System.IO.File]::Exists($Exe) -or $(Test-CommandOnPath $Exe)) {
        $isOpenJDK = & $Exe -version 2>&1 | Select-String -SimpleMatch 'OpenJDK' -Quiet
        if ($isOpenJDK) {
            # We can try and find a more specific value.
            $m = & $Exe -version 2>&1 | Select-Object -Skip 1 -First 1 | Select-String -Pattern '[a-zA-Z]+-([0-9]+[.]){2,}'
            if ($m.Matches) {
                $comp = $m.Matches.Value.Split('-')
                if ($comp.Count -eq 2) {
                    # promising
                    return $comp[0]
                }
            }
            return 'OpenJDK'
        }
        else {
            return 'Oracle'
        }
    }
    else {
        throw "$Exe does not seem to exist (or is not a file)!"
    }
}

function Get-JavaHomeVar {
    # .NET calls them 'Machine' vars, but in the UI they are typically referred to as 'System variables'
    $systemVars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine)
    $userVars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::User)

    $rv = @{}

    if ($systemVars.ContainsKey('JAVA_HOME')) {
        $rv['System'] = $systemVars['JAVA_HOME']
    }

    if ($userVars.ContainsKey('JAVA_HOME')) {
        $rv['User'] = $userVars['JAVA_HOME']
    }
    
    $rv
}

function Get-DefaultJavaHome {
    if (Test-CommandOnPath 'java.exe') {
        $m = & 'java.exe' -XshowSettings -version 2>&1 | Select-String -Pattern 'java.home = .+'
        if ($m.Matches) {
            $comp = $m.Matches.Value.Split('=')
            if ($comp.Count -eq 2) {
                return $comp[1].Trim()
            }
        }
    }
    return $null
}

function Test-DefaultIsJRE {
    # It is actually a bit tricky to figure out if the default version is a JDK or the JRE
    # because newer versions of Java deliver shim binaries similar to the ones found on macOS.
    # Thus, we need to resort to a bit of a heuristic.
    $hasCompiler = Test-CommandOnPath 'javac.exe'
    $hasRuntime = Test-CommandOnPath 'java.exe'

    if ($hasRuntime -and $hasCompiler) {
        $rtPath = (Get-Command 'java.exe' | Get-Item).DirectoryName
        $compPath = (Get-Command 'javac.exe' | Get-Item).DirectoryName

        if ($rtPath -ne $compPath) {
            return $true
        }

        # Not quite done yet...
        $runtimeVersion = Get-JavaVersion 'java.exe'
        $compilerVersion = Get-JavaVersion 'javac.exe'

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
        return $true # -> it is just the JRE
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

    $compiler = [System.IO.Path]::Combine($InstallLocation, 'bin\javac.exe')
    $runtime = [System.IO.Path]::Combine($InstallLocation, 'bin\javac.exe')

    [System.IO.File]::Exists($compiler) -and [System.IO.File]::Exists($runtime)
}

function Get-JavaHomeFacts {
    Param(
        [string]$JavaHome
    )

    if (-not (Test-Path $JavaHome)) {
        Write-Host -ForegroundColor Red "JAVA_HOME seems to point to an invalid location: ${JavaHome}"
        return @{ Version = '0.0.0'; Feature = 0; JDK = $false; Vendor = $null; Arch = $null; JavaHome = $JavaHome }
    }

    $javaExe = [System.IO.Path]::Combine($JavaHome, 'bin\java.exe')
    $ver = Get-JavaVersion $javaExe
    $feature = Get-JavaFeatureVersion $ver
    $isJDK = Test-IsJDK $JavaHome
    $vendor = Get-JavaVendor $javaExe
    $bitness = Get-Bitness $javaExe

    if ($bitness -eq 32) {
        $arch = 'x86'
    }
    elseif ($bitness -eq 64) {
        $arch = 'x64'
    }
    else {
        throw "Unxpected: Bitness reported as ${bitness}-bit"
    }

    return @{ Version = $ver; Feature = $feature; JDK = $isJDK; Vendor = $vendor; Arch = $arch; JavaHome = $JavaHome }
}

function Get-DefaultJavaFacts {
    $ver = Get-JavaVersion 'java.exe'
    $feature = Get-JavaFeatureVersion $ver
    $isJRE = Test-DefaultIsJRE
    $vendor = Get-JavaVendor 'java.exe'
    $bitness = Get-Bitness (Get-Command 'java.exe').Source
    $javaHome = Get-DefaultJavaHome

    if ($bitness -eq 32) {
        $arch = 'x86'
    }
    elseif ($bitness -eq 64) {
        $arch = 'x64'
    }
    else {
        throw "Unxpected: Bitness reported as ${bitness}-bit"
    }

    return @{ Version = $ver; Feature = $feature; JDK = -not $isJRE; Vendor = $vendor; Arch = $arch; JavaHome = $javaHome }
}

function Convert-JavaFacts {
    Param(
        [parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [hashtable] $JavaFacts
    )

    $package = if ($JavaFacts.JDK) { 'JDK' } else { 'JRE' }

    return "$($JavaFacts.Vendor) ${package} $($JavaFacts.Feature) ($($JavaFacts.Version)) for $($JavaFacts.Arch)"
}
#endregion

#region user interaction helpers
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

    Write-Host -ForegroundColor DarkGray -NoNewline "${Title}: "
    Write-Host -ForegroundColor Gray $Message
}

function Write-AncientVersionWarning {
    Param(
        [string] $ActionMessage
    )

    Write-Host -ForegroundColor Yellow @"

It looks like you have Oracle Java 6 or older installed. Note that this Java version is very old, is no longer
supported, and hasn't received any updates in years. Unless you have it on your machine for specific reasons
(e.g. to run a piece of legacy software) it is highly recommended to switch to a supported version of Java. 

Temurin does not provide compatible OpenJDK builds for Java 6 or older.
Therefore ${ActionMessage}.

"@
}

function Write-DeprecatedVersionInfo {

    Write-Host -ForegroundColor Yellow @"
Java 7 is no longer supported and Temurin does not provide builds for it. Replacing it with Java 8 is likely a safe
and sane option. That said, there is a slim chance that some older Java applications will not run properly under Java 8.

"@

}

function Write-JREInfo {
    Write-Host @"

It seems that you have at least one version of Oracle JRE installed. Apart from the JVM, Oracle's JRE ships with two
components that never have been open-sourced:

  - support for Java applets (run Java applications inside a browser)
  - support for Java Web Start (start Java applications from within a browser)

As Temurin JRE cannot include these proprietary extensions, it is not a 1:1 replacement for Oracle. That said, Java
applets are deprecated for a long time and it is unlikely that you still need this functionality.

Java Web Start is deprecated too as of Java 9, however it is still used sometimes. If you still need support for
Java Web Start, I would recommend that you check out Open Web Start (https://openwebstart.com/) which offers an
open source replacement for Java Web Start.

If you don't care about applets or Web Start and just have the JRE installed because you want a Java runtime without
any of the developer tools, replacing Oracle JRE with Temurin is a reasonable choice.

"@
}

function Write-CorrettoWarning {
    Write-Host -ForegroundColor Yellow @"
It seems that you have at least one version of Amazon Corretto installed. Because Corretto makes it annoyingly hard
to determine its install location, this script will ignore Corretto installations for the most part. There is now
real harm in it, but you might end up with some extra Temurin JDKs although Corretto could be used. Also, the default
Java might get switched to Temurin if it was Corretto before.

If you like your Corretto, then I suggest to stop now. If on the other hand, you think that Temurin is cool too
(or you don't care) you may safely continue.
"@
}

function Write-OracleLicenseWarning {
    Write-Host -ForegroundColor Yellow @"
As of April 16, 2019, Oracle has changed the license under which Java is released. Under the new conditions certain
uses, such as personal use and development use are still allowed at no cost, yet other uses authorized under the prior
license terms are no longer free.

It is highly recommended that you replace this version of Java with Eclipse Temurin, particularly if you use it in a
commercial setting.

"@
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
        }
        else {
            return $answer -eq 'y'
        }
    }
}

function Receive-AnswerInfo {
    Param(
        [string] $Question
    )

    $answer = $null
    while (-not $answer) {
        $answer = Read-Host -Prompt "${Question} [y/n] (or [i] if you need more info)"
        if ($answer.ToLowerInvariant() -ne 'y' -and $answer.ToLowerInvariant() -ne 'n' -and $answer.ToLowerInvariant() -ne 'i') {
            Write-Host -ForegroundColor DarkGray "Please just answer with either 'y', 'n' or 'i."
            $answer = $null
        }
        else {
            return $answer
        }
    }
}
#endregion

#region OpenJDK helpers
function Test-CanConnect {
    curl.exe -s -I -o $null -f $AdoptiumAPI
    return $?
}

function Get-TemurinInstaller {
    Param(
        [ValidateScript({ $_ -eq 'jdk' -or $_ -eq 'jre' })]
        [string] $Package = 'jdk',
        [ValidateScript({ $_ -eq 'x64' -or $_ -eq 'x86' })]
        [string] $Arch = 'x64',
        [parameter(Mandatory = $true)]
        [int] $FeatureVersion,
        [parameter(Mandatory = $true)]
        [string] $TmpDir
    )

    $url = "${AdoptiumAPI}/v3/installer/latest/${FeatureVersion}/ga/windows/${Arch}/${Package}/hotspot/normal/eclipse"
    $fileName = "temurin-${Flavor}-${FeatureVersion}.msi"
    $outFile = [System.IO.Path]::Combine($TmpDir, $fileName)
    
    $status = curl.exe -s -w '%{http_code}' $url

    if ($status -eq 307) {
        curl.exe -s -L -o $outFile $url
        if (-not $?) {
            throw "Failed to download installer for Temurin Java ${FeatureVersion} ($($Package.ToUpperInvariant()))."
        }
    }
    else {
        throw "Failed to get download URL for Temurin Java ${FeatureVersion} ($($Package.ToUpperInvariant()))."
    }

    $outFile
}

function Install-Temurin {
    Param(
        [parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string] $MsiInstaller,
        [ValidateScript({ $_ -eq 'x64' -or $_ -eq 'x86' })]
        [string] $Arch,
        [ValidateScript({ $_ -eq 'jdk' -or $_ -eq 'jre' })]
        [string] $Package
    )

    Start-Process -Wait -Verb RunAs -FilePath 'msiexec' -ArgumentList '/i', "`"$MsiInstaller`"", '/quiet', '/norestart', '/qn'

    # Unfortunately, msiexec might report success even if the package was in fact not installed. So we need to double check.
    if ($?) {
        $temurin = Get-InstalledSoftware | Where-Object { $_.AppName -and $_.AppName.Contains('Temurin') -and $_.AppName.Contains($Arch) -and $_.AppName.Contains($Package.ToUpperInvariant()) }
        if ($temurin) {
            return $true
        }
        return $false
    }
    return $false
}

function Test-HasCorretto {
    $oracle, $openJDKs = Get-JavaInstallations
    ($openJDKs | Where-Object { $_.AppName -and $_.AppName.Contains('Corretto') }).Count -gt 0
}
#endregion

#region remove and replace Oracle installs
function _nukeOracleJavas {
    Param(
        [Object[]] $Candidates
    )

    Write-Subtitle 'Removal' 'Uninstalling Oracle Javas'
    foreach ($morturi in $Candidates) {
        $facts = Get-JavaHomeFacts $morturi.InstallLocation
        Write-Host "Uninstalling $($facts | Convert-JavaFacts). Please be patient. This might take a while."
        
        $rv = Uninstall-InstalledSoftware $morturi.AppGUID
        if ($rv -ne 0) {
            Write-Host -ForegroundColor Red "Failed to uninstall $($facts | Convert-JavaFacts)!"
        }
        else {
            Write-Host -ForegroundColor Green "Uninstalled $($facts | Convert-JavaFacts)!"
            $global:RemovedJavaHomes += $facts.JavaHome
        }
    }
}

function _downloadAndInstall {
    Param(
        [string] $Arch,
        [string] $Package,
        [int] $FeatureVersion
    )

    while ($true) {
        try {
            $installer = Get-TemurinInstaller -Package $Package -Arch $Arch -FeatureVersion $FeatureVersion -TmpDir $global:DownloadDir
            break
        }
        catch {
            Write-Host -ForegroundColor Red $_
            if (-not (Receive-Answer 'Do you want to try again?')) {
                Write-Host 'Giving up!'
                return $false
            }
        }
    }

    Write-Host "Installing Temurin $($Package.ToUpperInvariant()) ${FeatureVersion}."
    while ($true) {
        if (-not (Install-Temurin -MsiInstaller $installer -Arch $Arch -Package $Package)) {
            Write-Host -ForegroundColor Red "Failed to install Temurin $($Package.ToUpperInvariant())!"
            if (-not (Receive-Answer 'Do you want to try again?')) {
                Write-Host 'Giving up!'
                return $false
            }
        }
        else {
            Write-Host -ForegroundColor Green "Temurin $($Package.ToUpperInvariant()) successfully installed!"
            return $true
        }
    }
}

function _checkAndDownloadTemurinJRE {
    Param(
        [string] $Arch,
        [int] $FeatureVersion,
        [Object[]] $Installs
    )

    Write-Host "Checking if Temurin JRE ($(if ($Arch -eq 'x64') { '64-bit' } else { '32-bit' })) or other equivalent OpenJDK is already installed."
    if ($Installs.Count -gt 0) {
        Write-Host -ForegroundColor Green 'Found! Skipping download and installation.'
        return $true
    }
    else {
        Write-Host -ForegroundColor Yellow 'Not found! Will download and install Temurin JRE. (Please be patient.)'
        _downloadAndInstall -Arch $Arch -Package 'jre' -FeatureVersion $FeatureVersion
    }   
}
function _dealWithJDKs {
    # JDKs
    Write-Title 'Java Development Kits (JDKs)'
    Write-Subtitle 'OpenJDK' 'Looking for OpenJDK installations on the system.'
    $allOracle, $allOpenJDKs = Get-JavaInstallations
    $openJDKs = $allOpenJDKs | Where-Object { $_.AppName.Contains('JDK') -and $_.InstallLocation }

    $availableFeatureVersions = @{}
    $toReplace = @()
    $toRemove = @()
    if (-not $openJDKs) {
        Write-Host 'No installations found!'
    }

    foreach ($oj in $openJDKs) {
        $facts = Get-JavaHomeFacts $oj.InstallLocation
        Write-Host -ForegroundColor Green "- Found $($facts | Convert-JavaFacts)!"
        $key = "$($facts.Feature)-$($facts.Arch)"
        $availableFeatureVersions[$key] = $facts
    }

    Write-Host ''
    Write-Subtitle 'Oracle JDKs' 'Looking for Oracle JDK installations on the system.'
    $oracleJDKs = $allOracle | Where-Object { $_.AppName.Contains("Develop") }
    if (-not $oracleJDKs) {
        Write-Host -ForegroundColor Green 'No installations found!'
    }

    foreach ($oracle in $oracleJDKs) {
        $facts = Get-JavaHomeFacts $oracle.InstallLocation
        $replace = $false
        Write-Host -NoNewline -ForegroundColor Yellow "Found $($facts | Convert-JavaFacts)"
        if ($facts.Feature -lt 7) {
            Write-Host -ForegroundColor Red ' (ancient version)!'
        }
        elseif ($facts.Feature -lt 8) {
            Write-Host -ForegroundColor Yellow ' (deprecated version)!'
        }
        elseif (Test-IsNewLic $facts.Version) {
            Write-Host -ForegroundColor Red ' (new license)!'
        }
        else {
            Write-Host -ForegroundColor Yellow '!'
        }
        $q = "Do you want to replace Oracle JDK $($facts.Feature)?"

        if ($facts.Feature -lt 8 -or (Test-IsNewLic $facts.Version)) {
            $resp = Receive-AnswerInfo $q
        }
        else {
            $resp = if (Receive-Answer $q) { 'y' } else { 'n' }
        }

        if ($resp -eq 'i') {
            if ($facts.Feature -lt 7) {
                Write-AncientVersionWarning 'some Java applications might no longer work if it is replaced with Temurin JDK'
            }
            elseif ($facts.Feature -lt 8) {
                Write-DeprecatedVersionInfo
            }
            elseif (Test-IsNewLic $facts.Version) {
                Write-OracleLicenseWarning
            }
            $replace = Receive-Answer $q
        }
        elseif ($resp -eq 'y') {
            $replace = $true
        }

        if ($replace) {
            Write-Host "Excellent! Marking it for removal and replacement."
            $toReplace += $oracle
        }
        else {
            Write-Host "Fine. I won't touch it."
        }
        Write-Host ''
    }

    if ($toReplace) {
        Write-Subtitle 'Replacement' 'Installing Temurin JDKs if necessary'
    }

    foreach ($morturi in $toReplace) {
        $facts = Get-JavaHomeFacts $morturi.InstallLocation
        $jdkFeature = $facts.Feature
        if ($jdkFeature -lt 8) {
            $jdkFeature = 8
        }

        Write-Host "Checking if a replacement JDK for $($facts | Convert-JavaFacts) is already installed."
        $key = "${jdkFeature}-$($facts.Arch)"
        $replacementExists = $availableFeatureVersions.ContainsKey($key)

        if ($replacementExists) {
            Write-Host -ForegroundColor Green "Found! $($availableFeatureVersions[$key] | Convert-JavaFacts) is a suitable replacement. Skipping download and installation."
            $toRemove += $morturi
        }
        else {
            Write-Host -ForegroundColor Yellow 'Not found! Will download and install replacement Temurin JDK. (Please be patient.)'
            if (_downloadAndInstall -Arch $facts.Arch -Package 'jdk' -FeatureVersion $jdkFeature) {
                $toRemove += $morturi
                $key = "${jdkFeature}-$($facts.Arch)"
                # Need to fake it a little bit...
                $availableFeatureVersions[$key] = @{ Version = 'just installed'; Feature = $facts.Feature; JDK = $true; Vendor = 'Temurin'; Arch = $facts.Arch; JavaHome = $null }
            }
            else {
                Write-Host -ForegroundColor Red "Installation of Temurin JDK failed. Won't remove Oracle JDK!"
            }
        }

        Write-Host ''
    }

    if ($toRemove) {
        _nukeOracleJavas $toRemove
    }

    Write-Host ''
}

function _dealWithJRE {
    # JRE
    Write-Title 'Java Runtime Environment (JRE)'
    Write-Subtitle 'Oracle JRE' 'Looking for Oracle JRE installations on the system.'
    $allOracle, $allOpenJDKs = Get-JavaInstallations
    $oracleJREs = $allOracle | Where-Object { -not $_.AppName.Contains("Develop") }
    $openJREs = $allOpenJDKs | Where-Object { $_.AppName -and $_.AppName.Contains('JRE') -and $_.InstallLocation }
    $openJREsX86 = $openJREs | Where-Object { $_.SoftwareArchitecture -and $_.SoftwareArchitecture -eq 'x86' }
    $openJREsX64 = $openJREs | Where-Object { $_.SoftwareArchitecture -and $_.SoftwareArchitecture -eq 'x64' }

    # Note: Since on Windows the JRE is not as 'special' as on macOS, we could also do JREs and JDKs in one go,
    # but we are trying to stay somewhat close to the macOS version.
    $toRemove = @()
    $needX86JRE = $False
    $needX64JRE = $False

    if (-not $oracleJREs) {
        Write-Host -ForegroundColor Green 'No installations found!'
    }

    foreach ($jre in $oracleJREs) {
        $facts = Get-JavaHomeFacts $jre.InstallLocation
        $replace = $False
        Write-Host -NoNewline -ForegroundColor Yellow "Found $($facts | Convert-JavaFacts)"

        if ($facts.Feature -lt 7) {
            Write-Host -ForegroundColor Red ' (ancient version)!'
        }
        elseif ($facts.Feature -lt 8) {
            Write-Host -ForegroundColor Yellow ' (deprecated version)!'
        }
        elseif (Test-IsNewLic $facts.Version) {
            Write-Host -ForegroundColor Red ' (new license)!'
        }
        else {
            Write-Host -ForegroundColor Yellow '!'
        }
        $q = "Do you want to replace Oracle JRE $($facts.Feature)?"
        $resp = Receive-AnswerInfo $q

        if ($resp -eq 'i') {
            Write-JREInfo
            if ($facts.Feature -lt 7) {
                Write-AncientVersionWarning 'some Java applications might no longer work if it is replaced with Temurin JRE'
            }
            elseif ($facts.Feature -lt 8) {
                Write-DeprecatedVersionInfo
            }
            elseif (Test-IsNewLic $facts.Version) {
                Write-OracleLicenseWarning
            }
            $replace = Receive-Answer $q
        }
        elseif ($resp -eq 'y') {
            $replace = $true
        }

        if ($replace) {
            Write-Host "Excellent! Marking it for removal and replacement."
            $toRemove += $jre
            if ($facts.Arch -eq 'x86') {
                $needX86JRE = $true
            }
            elseif ($facts.Arch -eq 'x64') {
                $needX64JRE = $true
            }
        }
        else {
            Write-Host "Fine. I won't touch it."
        }

        Write-Host ''
    }

    # Oracle doesn't publish JREs for Java > 8 anymore, so we just need to make sure that a OpenJDK JRE 8 is available.
    if ($toRemove) {
        Write-Subtitle 'Replacement' 'Installing Temurin JRE if necessary'
        $canNukeX86 = $false
        $canNukeX64 = $false
        if ($needX86JRE) {
            if (_checkAndDownloadTemurinJRE 'x86' 8 $openJREsX86) {
                Write-Host ''
                $canNukeX86 = $true
            }
        }

        if ($needX64JRE) {
            if (_checkAndDownloadTemurinJRE 'x64' 8 $openJREsX64) {
                Write-Host ''
                $canNukeX64 = $true
            }
        }

        if ($canNukeX86 -and $canNukeX64) {
            _nukeOracleJavas $toRemove
        }
        elseif ($canNukeX86 -and -not $canNukeX64) {
            _nukeOracleJavas ($toRemove | Where-Object { $_.SoftwareArchitecture -eq 'x86' })
        }
        elseif ($canNukeX64 -and -not $canNukeX86) {
            _nukeOracleJavas ($toRemove | Where-Object { $_.SoftwareArchitecture -eq 'x64' })
        }
    }

    Write-Host ''
}
#endregion

#region pre checks
function _precheckPSVersion {
    Write-Subtitle 'PowerShell' 'Checking if we are running in PowerShell version 5 or later.'

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host -ForegroundColor Red "This script requires at least PowerShell version 5 to run, but this is version $($PSVersionTable.PSVersion.Major)!"
        Write-Host 'Exiting.'
        exit
    }
    else {
        Write-Host -ForegroundColor Green "All good. Looks like this is PowerShell version $($PSVersionTable.PSVersion.Major)!"
        Write-Host ''
    }
}

function _precheckShellElevation {
    Write-Subtitle 'Admin Rights' 'Checking if we are running in an elevated shell.'

    $restartRequired = $false
    if (Test-Elevated) {
        Write-Host -ForegroundColor Green "Swell! It looks like we are running in an elevated shell!`r`n"
    }
    elseif (Test-IsInLocalAdmins) {
        Write-Host -ForegroundColor DarkGreen @"
Great! It looks like your account is a local admin. Yet we are not running in an elevated prompt. This script requires
admin privileges to install and uninstall software and modify environment variables if need be.

Therefore I will try and switch to an elevated shell now if you allow. If not, execution has to stop here.
"@
        $restartRequired = $true
    }
    else {
        Write-Host -ForegroundColor Yellow @"
Warning! Could not determine if your account has local admin rights. It is possible that you do if e.g. your account
inherits the right indirectly via AD group membership. However determining this is beyond the capabilities of this
little script.

If you know that you are admin (or if you know the credentials of a local admin account on the system), you may go on.
If not you better stop now and ask an admin for help.
"@
        $restartRequired = $true
    }

    if ($restartRequired) {
        $global:Elevated = $true
        if (Receive-Answer "Attempt restart in an elevated shell? (Script will stop if answer is 'n'.)") {
            Restart-HostElevated
        }
        else {
            Write-Host 'Okay. See you later!'
            exit
        }
    }
}

function _precheckCurl {
    Write-Subtitle 'cURL' 'Checking if curl.exe is available'

    if (Test-CommandOnPath 'curl.exe') {
        Write-Host -ForegroundColor Green "Splendid! curl.exe is available!"
        Write-Host ''
    }
    else {
        Write-Host -ForegroundColor Red "curl.exe could not be found!`r`n"
        Write-Host -ForegroundColor Yellow @"
Microsoft ships curl.exe with Windows 10 and 11 since 2017, however it looks like it is not available on
your computer. curl.exe is required to download Temurin installers and this script cannot function without
it.

I suggest that you head over to https://curl.se/windows/ and grab the current version for Windows. Once
installed, you may re-run this script.

Bye for now!
"@
        exit
    }
}

function _precheckDefaultJava {
    Write-Subtitle 'Default Installation' 'Looking for a default Java installation and checking JAVA_HOME.'

    $ver = Get-JavaVersion 'java.exe'
    if ($ver -ne '0.0.0') {
        $global:DefaultJavaFacts = Get-DefaultJavaFacts
        Write-Host "- It looks like at least one version of Java is installed: $($DefaultJavaFacts | Convert-JavaFacts)"

        if (-not $global:DefaultJavaFacts.JDK -and (Test-CommandOnPath 'javac.exe')) {
            $javacFeatureVersion = Get-JavaVersion 'javac.exe' | Get-JavaFeatureVersion
            $javacArch = if (64 -eq (Get-Bitness (Get-Command 'java.exe').Source)) { 'x64' } else { 'x86' }
            $compilerPath = (Get-Command 'javac.exe').Source
            $global:DefaultJavaCompilerFacts = @{ Arch = $javacArch; JDK = $true; Feature = $javacFeatureVersion; CompilerPath = $compilerPath; }
        }

        if ($global:DefaultJavaFacts.Feature -lt 7) {
            # TODO: Right decision? We could probably continue...
            Write-AncientVersionWarning 'execution of this script will now stop'
            Exit
        }
        
    }
    else {
        Write-Host "Could not find a default Java installation."
    }

    $jhome = Get-JavaHomeVar
    if ($jhome.Count -gt 0) {
        if ($jhome.ContainsKey('System') -and -not $jhome.ContainsKey('User')) {
            Write-Host "- It looks like a system-wide environment variable JAVA_HOME is set and is pointing to:  $($jhome['System'])"
            $global:SystemJavaHomeFacts = Get-JavaHomeFacts $jhome['System']
        }
        elseif ($jhome.ContainsKey('User') -and -not $jhome.ContainsKey('System')) {
            Write-Host "- It looks like the user-specific environment variable JAVA_HOME is set and is pointing to:  $($jhome['User'])"
            $global:UserJavaHomeFacts = Get-JavaHomeFacts $jhome['User']
        }
        else {
            # System has both system-wide and per-user JAVA_HOME set.
            Write-Host "- It looks like a system-wide environment variable JAVA_HOME is set and is pointing to:  $($jhome['System'])"
            Write-Host "  In addition, a user-specific variable is set (overriding the system-wide variable) and is pointing to:`r`n  $($jhome['User'])"
            $global:UserJavaHomeFacts = Get-JavaHomeFacts $jhome['User']
            $global:SystemJavaHomeFacts = Get-JavaHomeFacts $jhome['System']
        }
    }
    else {
        Write-Host 'It seems that the environment variable JAVA_HOME is not set.'
    }

    Write-Host ''
}

function _precheckConnectivity {
    Write-Subtitle 'Connectivity' "Trying to reach the Adoptium API at ${AdoptiumAPI}"
    if (Test-CanConnect) {
        Write-Host -ForegroundColor Green "Excellent! Adoptium API is responding!`r`n"
    }
    else {
        Write-Host -ForegroundColor Red 'Failed to connect!'
        Write-Host ''
        Write-Host -ForegroundColor Yellow @"
Trying to connect to ${AdoptiumAPI} resulted in an error. This script requires an active Internet connection to
proceed. Please verify that your machine is connected to the Internet and that ${AdoptiumAPI} can be reached.
"@
        Write-Host ''
        Write-Host 'Exiting now!'
        exit
    }
}

function _precheckCorretto {
    # Amazon Corretto
    Write-Subtitle 'Corretto' 'Checking if Amazon Corretto OpenJDK is installed.'
    if (Test-HasCorretto) {
        Write-CorrettoWarning
        if (Receive-Answer 'Do you want to stop now?') {
            Write-Host 'Fair enough. Bye!'
            Exit
        }
        else {
            Write-Host "Cool! Let's continue."
        }
    }
    else {
        Write-Host -ForegroundColor Green 'No Corretto installations found.'
    }
    Write-Host ''
}

function _prechecks {
    Write-Title 'Initial Checks'
    _precheckPSVersion
    _precheckShellElevation
    _precheckCurl
    _precheckDefaultJava
    _precheckConnectivity
    _precheckCorretto
}
#endregion

#region post checks
function Test-GotKilled {
    param([string] $JavaHome)

    Write-Debug "Checking if $JavaHome is in the victims' list"
    foreach ($victim in $global:RemovedJavaHomes) {
        Write-Debug "Found victim $victim"
        # Doing it this way because of nested 'jre' folders
        if ($JavaHome.StartsWith($victim) -or $victim.StartsWith($JavaHome)) {
            return $true
        } 
    }

    return $false
}

function Test-CompilerGotKilled {
    param([string] $CompilerPath)

    if ($CompilerPath.Contains('Common Files')) {
        # This is the shim...
        return -not (Test-Path $CompilerPath)
    }
    else {
        return Test-GotKilled $CompilerPath
    }
}

function Find-ReplacementJavaHome {

    param([hashtable] $Facts)

    Write-Debug "Looking for replacement for: $($Facts.Feature), $($Facts.Arch), JDK: $($Facts.JDK)"

    if (-not $global:NewInstalls) {
        $oracle, $openjdk = Get-JavaInstallations -Refresh
        $global:NewInstalls = $openjdk | Where-Object { $_.InstallLocation }
    }

    $cand = $null
    foreach ($java in $global:NewInstalls) {
        $f = Get-JavaHomeFacts $java.InstallLocation
        Write-Debug "Considering: $($Facts.Feature), $($Facts.Arch), JDK: $($Facts.JDK)"
        if ($f.Feature -eq $Facts.Feature -and $f.Arch -eq $Facts.Arch -and $f.JDK -eq $Facts.JDK) {
            $cand = $f.JavaHome
            break
        }
    }

    if (-not $cand -and -not $Facts.JDK) {
        # If we are looking for a replacement for a JRE, we can retry and see if there is a JDK that fits.
        foreach ($java in $global:NewInstalls) {
            $f = Get-JavaHomeFacts $java.InstallLocation

            if ($f.Feature -eq $Facts.Feature -and $f.Arch -eq $Facts.Arch) {
                $cand = $f.JavaHome
                break
            }
        }
    }

    return $cand
}

function _postFixJavaHome {
    Write-Subtitle 'JAVA_HOME' 'Checking if it needs updating'

    if ($global:SystemJavaHomeFacts) {
        Write-Host 'Checking system-wide JAVA_HOME.'
        $p = $global:SystemJavaHomeFacts.JavaHome
        # Check if we killed it.
        if ($p -and (Test-GotKilled $p)) {
            Write-Host -ForegroundColor Yellow 'Looks like the system-wide JAVA_HOME variable requires an update.'
            $cand = Find-ReplacementJavaHome -Facts $global:SystemJavaHomeFacts

            if ($cand) {
                Write-Host -ForegroundColor Green "Set the system-wide JAVA_HOME environment variable to ${cand}"
                [System.Environment]::SetEnvironmentVariable('JAVA_HOME', $cand, [System.EnvironmentVariableTarget]::Machine)
            }
            else {
                Write-Host -ForegroundColor Red "Unexpected! Could not find a suitable replacment for JAVA_HOME pointing to '${p}'!"
            }
        }
        else {
            Write-Host -ForegroundColor Green 'Looks like no change is required.'
        }
        Write-Host ''
    }

    if ($global:UserJavaHomeFacts) {
        Write-Host 'Checking per-user JAVA_HOME.'
        $p = $global:UserJavaHomeFacts.JavaHome
        # Check if we killed it.
        if ($p -and (Test-GotKilled $p)) {
            Write-Host -ForegroundColor Yellow 'Looks like the per-user JAVA_HOME variable requires an update.'
            $cand = Find-ReplacementJavaHome -Facts $global:UserJavaHomeFacts

            if ($cand) {
                Write-Host -ForegroundColor Green "Set the per-user JAVA_HOME environment variable to ${cand}"
                [System.Environment]::SetEnvironmentVariable('JAVA_HOME', $cand, [System.EnvironmentVariableTarget]::User)
            }
            else {
                Write-Host -ForegroundColor Red 'Unexpected! Could not find a suitable replacment for JAVA_HOME!'
                Write-Host -ForegroundColor Red "It used to point to ${p}"
            }
        }
        else {
            Write-Host -ForegroundColor Green 'Looks like no change is required.'
        }
        Write-Host ''
    }

    if (-not $global:SystemJavaHomeFacts -and -not $global:UserJavaHomeFacts) {
        Write-Host -ForegroundColor Green 'Looks like no changes are required.'
        Write-Host ''
    }
}

function _postRefreshPath {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    if (-not ("Win32.NativeMethods" -as [Type])) {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
    }

    [Win32.Nativemethods]::SendMessageTimeout([IntPtr] 0xffff, 0x1a, [UIntPtr]::Zero, "Environment", 2, 5000, [ref][UIntPtr]::Zero) | Out-Null
}

function _postFixPath {
    Write-Subtitle 'PATH' 'Checking if it needs updating'

    $fstPathEntry = $null
    $sndPathEntry = $null
    if ($global:DefaultJavaFacts) {
        Write-Debug "Got default Java facts. It was $($global:DefaultJavaFacts | Convert-JavaFacts) located at $($global:DefaultJavaFacts.JavaHome)"
        $jh = $global:DefaultJavaFacts.JavaHome
        $killed = Test-GotKilled $jh
        if ($jh -and $killed) {
            Write-Debug "I believe that we nuked the path..."
            # Seems so. Well, okay. Let's see if we can find a suitable replacement.
            $candRuntime = Find-ReplacementJavaHome $global:DefaultJavaFacts
            Write-Debug "Found candRuntime to be ${candRuntime}"
            if ($candRuntime) {
                $fstPathEntry = [System.IO.Path]::Combine($candRuntime, 'bin')
            }
        } elseif($jh -and -not $killed) {
            # Make sure the entry remains the first on the path
            $fstPathEntry = [System.IO.Path]::Combine($jh, 'bin')
        }
    }

    if ($global:DefaultJavaCompilerFacts) {
        Write-Debug "Got default Java Compiler facts. It was the compiler for Java $($global:DefaultJavaCompilerFacts.Feature) ($($global:DefaultJavaCompilerFacts.Arch))  located at $($global:DefaultJavaCompilerFacts.CompilerPath)"
        $cPath = $global:DefaultJavaCompilerFacts.CompilerPath
        $killedCompiler = Test-CompilerGotKilled $cPath
        if ($cPath -and $killedCompiler) {
            Write-Debug "I believe that we nuked the path..."
            $candCompiler = Find-ReplacementJavaHome $global:DefaultJavaCompilerFacts
            Write-Debug "Found candCompiler to be ${candComiler}"
            if ($candCompiler) {
                $sndPathEntry = [System.IO.Path]::Combine($candCompiler, 'bin')
            }
        }
    }

    if ($fstPathEntry -and $sndPathEntry -and $fstPathEntry -eq $sndPathEntry) {
        $sndPathEntry = $null
    }

    if ($fstPathEntry) {
        $newPath = $fstPathEntry
        if ($sndPathEntry) {
            $newPath += ";${sndPathEntry}"
        }

        $curPath = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)

        foreach ($entry in $curPath.Split(';')) {
            # Path::Combine() never appends a trailing backslash, thus...
            if ($entry.EndsWith('\')) {
                $entry = $entry.TrimEnd('\')
            }

            if ($entry -eq $fstPathEntry -or ($sndPathEntry -and $entry -eq $sndPathEntry) -or (Test-GotKilled $entry) -or (Test-CompilerGotKilled $entry)) {
                Write-Debug "Skipping ${entry}"
                continue
            }
            else {
                Write-Debug "Appending ${entry}"
                $newPath += ";${entry}"
            }
        }

        Write-Host "Updating PATH such that the appropriate OpenJDK Java installation(s) appear(s) first."
        Write-Debug "New PATH:`r`n  ${newPath}"
        [System.Environment]::SetEnvironmentVariable('Path', $newPath, [System.EnvironmentVariableTarget]::Machine)

        Write-Host -ForegroundColor Green "And that's done too! You should be good!"
    }
    else {
        Write-Host -ForegroundColor Green "Looks like PATH doesn't require any changes."
    }

}

function _postCleanup {
    Write-Title 'Final Checks'
    _postFixJavaHome
    _postFixPath
}
#endregion

#region main
try {
    _prechecks
    $global:DownloadDir = New-TempDir
    _dealWithJRE
    _dealWithJDKs
    _postCleanup
}
finally {
    if ($global:DownloadDir) {
        Remove-Item -Recurse -Force $global:DownloadDir
    }
}

if (-not $global:Elevated) {
    Write-Debug "global:Elevated was ${global:Elevated}"
    _postRefreshPath
    Read-Host -Prompt "`r`nWe are done. Press <Return> to terminate this script"
}
#endregion
