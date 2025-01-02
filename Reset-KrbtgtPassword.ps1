function Reset-KrbtgtPassword {
    [CmdletBinding()]
    param (
        [string]$Domain = $env:USERDNSDOMAIN,  # Default to the current user's domain
        [int]$PasswordLength = 24  # Default password length
    )

    try {
        # Import the Active Directory module
        Import-Module ActiveDirectory -ErrorAction Stop

        # Verify passwords are synchronized across DCs before changing the password
        $isSynchronized = Verify-KrbtgtPasswordAcrossDCs
        if (-not $isSynchronized) {
            Write-Warning "Password synchronization issues detected across domain controllers. Aborting password reset."
            return
        }

        # Retrieve the krbtgt account details
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -Server $Domain
        if (-not $krbtgt) {
            Write-Error "Failed to retrieve krbtgt account details."
            return
        }

        # Check if the password has been changed in the last 24 hours
        $passwordLastSetUTC = ($krbtgt.PasswordLastSet).ToUniversalTime()
        $nowUTC = (Get-Date).ToUniversalTime()

        if (($nowUTC - $passwordLastSetUTC).TotalHours -lt 24) {
            Write-Warning "The krbtgt password was changed within the last 24 hours (on $passwordLastSetUTC). The password reset operation is being aborted."
            return
        }

        # Generate a secure random password
        Add-Type -AssemblyName System.Web
        $randomPassword = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, 4)
        $securePassword = ConvertTo-SecureString $randomPassword -AsPlainText -Force

        # Change the krbtgt password
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $securePassword -Server $Domain
        Write-Host "krbtgt password has been randomized and changed successfully on domain: $Domain" -ForegroundColor Green

        # Force replication to all domain controllers
        Invoke-ADReplicationSync -Target "*" -PassThru | ForEach-Object {
            Write-Host "Replication initiated to: $($_.Target)."
        }

        Write-Host "Process completed. Please consider performing the reset a second time after a short delay." -ForegroundColor Yellow

    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

function Verify-KrbtgtPasswordAcrossDCs {
    [CmdletBinding()]
    param ()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $domainControllers = Get-ADDomainController -Filter * |
            Select-Object -ExpandProperty HostName

        $results = @()

        foreach ($dc in $domainControllers) {
            try {
                $krbtgt = Get-ADUser -Identity "krbtgt" -Server $dc -Properties PasswordLastSet
                if ($krbtgt) {
                    # Normalize to UTC for consistent comparison
                    $utcTime = ($krbtgt.PasswordLastSet).ToUniversalTime()
                    $results += [PSCustomObject]@{
                        DomainController = $dc
                        PasswordLastSet  = $utcTime
                    }
                }
                else {
                    Write-Warning "Failed to retrieve KrbTgt account details from $dc."
                }
            }
            catch {
                Write-Warning "Error retrieving data from $dc : $_"
            }
        }

        # Ensure all domain controllers were successfully contacted
        if ($results.Count -ne $domainControllers.Count) {
            Write-Warning "Not all domain controllers responded. Cannot verify synchronization."
            return $false
        }

        # Find distinct PasswordLastSet values
        $distinctTimes = $results.PasswordLastSet | Select-Object -Unique

        if ($distinctTimes.Count -eq 1) {
            Write-Host "All domain controllers have the same PasswordLastSet value."
            $results | Format-Table -AutoSize
            return $true
        }
        else {
            Write-Warning "Mismatch detected in PasswordLastSet values!"
            # Group by the PasswordLastSet value to show which DCs match each distinct timestamp
            $results | Group-Object -Property PasswordLastSet | ForEach-Object {
                Write-Host "`nPasswordLastSet: $($_.Name.ToString("o"))"  # Print full datetime in ISO format
                $_.Group | Format-Table -AutoSize
            }
            return $false
        }
    }
    catch {
        Write-Error "An error occurred: $_"
        return $false
    }
}

# Example usage
Reset-KrbtgtPassword
