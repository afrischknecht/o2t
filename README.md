# o2t
Script to switch from Oracle Java to Temurin.

## Instructions
This repo contains a PowerShell script for Windows and a Bash script for macOS. Both work roughly in the same way:

1. Look for Oracle JREs on the system.
2. Look for Oracle JDKs on the system.
3. For every installation found, ask user if Oracle Java should be replaced by a corresponding version of Eclipse Temurin.
4. If user confirms, fetch Temurin installer for the corresponding feature release via the [Adoptium API](https://api.adoptium.net/) and install.
5. If installation is successful, remove (uninstall) Oracle Java.
6. (Windows only) Fix JAVA_HOME if it was defined and was pointing to a Java installation that got removed.
7. (Windows only) Fix PATH such that the replacement Temurin JDK or JRE becomes the new default Java.

### Windows
1. Open a PowerShell prompt.
2. Make sure that the execution policy allows execution of scripts:
```
PS> Get-ExecutionPolicy
Restricted
# Note: '-Scope Process' limits the change to the current prompt. No need to change it back afterwards.
PS> Set-ExecutionPolicy -ExecutionPolicy Unrestricted '-Scope Process'

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): Y
PS>
```
3. Get the script:
```
# Note: 'curl.exe' not 'curl'. The former invokes the native cURL binary, the latter is an alias for Invoke-WebRequest.
PS> curl.exe -o o2t.ps1 https://raw.githubusercontent.com/afrischknecht/o2t/v2.0.2/win/o2t.ps1
```
4. Execute it:
```
PS> .\o2t.ps1
```
5. Follow the on-screen instructions. Questions can be answered by typing either `y` or `n` followed by `↵ Return`. (Sometimes `i` is also offered as an option.)

## macOS
1. Open Terminal.
2. Get the script:
```
% curl -o o2t.sh https://raw.githubusercontent.com/afrischknecht/o2t/v2.0.2/mac/oracle2temurin.sh && chmod u+x o2t.sh
```
3. Execute it:
```
% ./o2t.sh
```
4. Follow the on-screen instructions. Questions can be answered by typing either `y` or `n`. (Sometimes `i` is also offered as an option.)
