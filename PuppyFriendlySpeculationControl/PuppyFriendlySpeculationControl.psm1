function Test-SpeculationControlSettings {
  <#

  .SYNOPSIS
  This function queries the speculation control settings for the system.

  .DESCRIPTION
  This function queries the speculation control settings for the system.

  Version 1.3.
  
  #>

  [CmdletBinding()]
  Param (
	  [switch]$silent
  )
    Begin {
        try {
            $ntdll = [Win32.ntdll]
        } catch {
            $NtQSIDefinition = "`n[DllImport(""ntdll.dll"")]`npublic static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);"
            $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru
        }

        [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

        $StatusObject = [Ordered]@{
            btiHardwarePresent = $false
            btiWindowsSupportPresent = $false
            btiWindowsSupportEnabled = $false
            btiDisabledBySystemPolicy = $false
            btiDisabledByNoHardwareSupport = $false
            kvaShadowRequired = $true
            kvaShadowPresent = $false
            kvaShadowEnabled = $false
            KvaShadowUserGlobal = $false
            kvaShadowPcidEnabled = $false
            KvaShadowInvpcid = $false
        }
        
    }
    Process {
        try {
            
            $TestParameters = @{
                StatusObject = ([ref]$StatusObject)
                systemInformationPtr = ([ref]$systemInformationPtr)
                returnLengthPtr = ([ref]$returnLengthPtr)
            }

            # Query branch target injection information.
            Test-BTI @TestParameters
            
            Write-Verbose ''

            # Query kernel VA shadow information.
            Test-KVA @TestParameters
            
            Write-Verbose ''
            
            # Provide guidance as appropriate.
            Get-SuggestedActions -StatusObject $StatusObject -silent:$silent
        
            return $StatusObject

        }
        finally
        {
            if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
            }

            if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
            }
        }
    }
    End {}
}

function Get-ProcessorInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ref]$StatusObject
    )
    $cpu = Get-WmiObject Win32_Processor | select -first 1

    if ($cpu.Manufacturer -eq "AuthenticAMD") {
        $StatusObject.Value.kvaShadowRequired = $false
    }
    elseif ($cpu.Manufacturer -eq "GenuineIntel") {
        $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
        $result = $regex.Match($cpu.Description)
            
        if ($result.Success) {
            $family = [System.UInt32]$result.Groups[1].Value
            $model = [System.UInt32]$result.Groups[2].Value
            $stepping = [System.UInt32]$result.Groups[3].Value
                
            if (($family -eq 0x6) -and ($model -in @(0x1c,0x26,0x27,0x36,0x35))) {
                $StatusObject.Value.kvaShadowRequired = $false
            }
        }
    }
    else {
        throw ("Unsupported processor manufacturer: {0}" -f $cpu.Manufacturer)
    }
}

function Get-SuggestedActions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$StatusObject,
		[Parameter()]
		[switch]$silent
    )
    
    [string[]]$actions = $(
        if (-not $StatusObject.btiHardwarePresent) {
            "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
        }

        if ((-not $StatusObject.btiWindowsSupportPresent) -or (-not $StatusObject.kvaShadowPresent)) {
            "Install the latest available updates for Windows with support for speculation control mitigations."
        }

        if ($StatusObject.btiHardwarePresent -and (-not $StatusObject.btiWindowsSupportEnabled) -or ($StatusObject.kvaShadowRequired -and (-not $StatusObject.kvaShadowEnabled))) {
            $HostOSType = @(@('Server','4072698'),@('Client','4073119'))
            $os = Get-WmiObject Win32_OperatingSystem

            "Follow the guidance for enabling Windows {0} support for speculation control mitigations described in https://support.microsoft.com/help/{1}" -f $HostOSType[[int]($os.ProductType -eq 1)]
        }
    )

    if ($actions.Length -gt 0) {
        Write-Verbose "Suggested actions" -Verbose:$(!$silent)

        foreach ($action in $actions) {
            Write-Verbose " * $action" -Verbose:$(!$silent)
        }
    }
}

function Test-QueryReturn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        $QueryResult,
        [Parameter(Mandatory=$true)]
        [string]$QueryTarget
    )

    if ($QueryResult -in @(0xc0000003,0xc0000002)) {
        $false
    }
    elseif ($QueryResult -ne 0) {
        throw (("Querying $QueryTarget information failed with error {0:X8}" -f $QueryResult))
    }
    else {
        $true
    }
}

function Test-BTI {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ref]$StatusObject,
        [Parameter(Mandatory=$true)]
        [ref]$systemInformationPtr,
        [Parameter(Mandatory=$true)]
        [ref]$returnLengthPtr
    )
    Begin{
        $scf = @{
            BpbEnabled = [System.UInt32]0x01
            BpbDisabledSystemPolicy = [System.UInt32]0x02
            BpbDisabledNoHardwareSupport = [System.UInt32]0x04
            HwReg1Enumerated = [System.UInt32]0x08
            HwReg2Enumerated = [System.UInt32]0x10
            HwMode1Present = [System.UInt32]0x20
            HwMode2Present = [System.UInt32]0x40
            SmepPresent = [System.UInt32]0x80
        }
        [System.UInt32]$systemInformationClass = 201
        [System.UInt32]$systemInformationLength = 4
        Write-Verbose "Speculation control settings for CVE-2017-5715 [branch target injection]"
    }
    Process {
        $btiQuery = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr.Value, $systemInformationLength, $returnLengthPtr.Value)

        if (Test-QueryReturn -QueryResult $btiQuery -QueryTarget 'branch target injection' -ErrorAction Stop){
            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr.Value)

            $StatusObject.Value.btiHardwarePresent = ((($flags -band $scf.HwReg1Enumerated) -ne 0) -or (($flags -band $scf.HwReg2Enumerated)))
            $StatusObject.Value.btiWindowsSupportPresent = $true
            $StatusObject.Value.btiWindowsSupportEnabled = (($flags -band $scf.BpbEnabled) -ne 0)

            if ($StatusObject.Value.btiWindowsSupportEnabled -eq $false) {
                $StatusObject.Value.btiDisabledBySystemPolicy = (($flags -band $scf.BpbDisabledSystemPolicy) -ne 0)
                $StatusObject.Value.btiDisabledByNoHardwareSupport = (($flags -band $scf.BpbDisabledNoHardwareSupport) -ne 0)
            }
            
            $scf.GetEnumerator() | %{
                Write-Verbose -Message " > $($_.Key)                   : $(($flags -band $_.Value) -ne 0)"
            }
        }
    }
    End{
        Write-Verbose " > Hardware support for branch target injection mitigation is present: $($StatusObject.Value.btiHardwarePresent)"
        Write-Verbose " > Windows OS support for branch target injection mitigation is present: $($StatusObject.Value.btiWindowsSupportPresent)"
        Write-Verbose " > Windows OS support for branch target injection mitigation is enabled: $($StatusObject.Value.btiWindowsSupportEnabled)"
  
        if ($StatusObject.Value.btiWindowsSupportPresent -and (-not $StatusObject.Value.btiWindowsSupportEnabled)) {
            Write-Verbose " > Windows OS support for branch target injection mitigation is disabled by system policy: $($StatusObject.Value.btiDisabledBySystemPolicy)"
            Write-Verbose " > Windows OS support for branch target injection mitigation is disabled by absence of hardware support: $($StatusObject.Value.btiDisabledByNoHardwareSupport)"
        }
    }

}

function Test-KVA {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ref]$StatusObject,
        [Parameter(Mandatory=$true)]
        [ref]$systemInformationPtr,
        [Parameter(Mandatory=$true)]
        [ref]$returnLengthPtr
    )

    Begin{
        $kvaFlags = @{
            kvaShadowEnabled = [System.UInt32]0x01
            kvaShadowUserGlobal = [System.UInt32]0x02
            kvaShadowPcid = [System.UInt32]0x04
            kvaShadowInvpcid = [System.UInt32]0x08
            kvaShadowPresent = ''
        }
        [System.UInt32]$systemInformationClass = 196
        [System.UInt32]$systemInformationLength = 4
    }
    Process {
        
        Write-Verbose "Speculation control settings for CVE-2017-5754 [rogue data cache load]"

        Get-ProcessorInfo -StatusObject ([ref]($StatusObject.Value))
            
        $kvaQuery = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr.Value, $systemInformationLength, $returnLengthPtr.Value)

        if (Test-QueryReturn -QueryResult $kvaQuery -QueryTarget 'kernel VA shadow' -ErrorAction Stop){
            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr.Value)

            [string[]]($StatusObject.Value.Keys | ?{$_ -match "^kva"}) | %{
                $StatusObject.Value[$_] = (($flags -band $kvaFlags[$_]) -ne 0)
            }

            $StatusObject.Value['kvaShadowPresent'] = $true

        }
    }
    End{
        Write-Verbose " > Hardware requires kernel VA shadowing: $($StatusObject.Value.kvaShadowRequired)"

        if ($StatusObject.Value.kvaShadowRequired) {

            Write-Verbose " > Windows OS support for kernel VA shadow is present: $($StatusObject.Value.kvaShadowPresent)"
            Write-Verbose " > Windows OS support for kernel VA shadow is enabled: $($StatusObject.Value.kvaShadowEnabled)"

            if ($StatusObject.Value.kvaShadowEnabled) {
                Write-Verbose "Windows OS support for PCID optimization is enabled: $($StatusObject.Value.kvaShadowPcidEnabled) [not required for security]"
            }
        }
    }

}