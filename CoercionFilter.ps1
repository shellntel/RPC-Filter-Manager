param(
    [Alias('h')]
    [switch]$help,
    [Alias('b')]
    [switch]$block,
    [Alias('a')]
    [switch]$permit,
    [Alias('l')]
    [switch]$list,
    [Alias('r')]
    [switch]$remove,
    [Alias('i')]
    [string]$interface
)

<#
.SYNOPSIS
    PowerShell script for managing RPC interface filters.
.DESCRIPTION
    Provides functions to block and check critical RPC interfaces for security hardening.
#>

# Define RPC interfaces with their friendly names
$RpcInterfaces = @{
    'MS-RPRN' = @{
        Description = 'Printer Bug'
        UUID = '12345678-1234-abcd-ef00-0123456789ab'
    }
    'MS-EFSRPC-1' = @{
        Description = 'PetitPotam'
        UUID = 'c681d488-d850-11d0-8c52-00c04fd90f7e'
    }
    'MS-EFSRPC-2' = @{
        Description = 'PetitPotam'
        UUID = 'df1941c5-fe89-4e79-bf10-463657acf44d'
    }
    'MS-FSRVP' = @{
        Description = 'Shadow Coerce'
        UUID = 'a8e0653c-2744-4389-a61d-7373df8b2292'
    }
    'MS-DFSNM' = @{
        Description = 'DFS Coerce'
        UUID = '4fc742e0-4a10-11cf-8273-00aa004ae673'
    }
    'MS-EVEN' = @{
        Description = 'Cheese Ounce'
        UUID = '82273fdc-e32a-18c3-3f78-827929dc23ea'
    }
    'MS-PAR' = @{
        Description = 'IRemoteWinspool'
        UUID = '76F03F96-CDFD-44FC-A22C-64950A001209'
    }

}

# Function definitions first
function Set-RpcInterfaceFilter {
    [CmdletBinding()]
    param(
        [string]$InterfaceName,
        [ValidateSet('block', 'permit')]
        [string]$Action = 'block'
    )

    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $filterCommands = "rpc filter`n"
        
        if ($InterfaceName) {
            if (-not $RpcInterfaces.ContainsKey($InterfaceName)) {
                throw "Invalid interface name. Use -h to see available interfaces."
            }
            $uuid = $RpcInterfaces[$InterfaceName].UUID
            Write-Host "`n$($Action.ToUpper())ING interface:" -ForegroundColor Yellow
            Write-Host "    - $InterfaceName ($($RpcInterfaces[$InterfaceName].Description))" -ForegroundColor Yellow
            Write-Host "    - UUID: $uuid`n" -ForegroundColor Yellow
            
            # Add audit=enable if action is permit
            $auditParam = ''
            if ($Action -eq 'permit') {
                $auditParam = ' audit=enable'
            }
            $filterCommands += @"
add rule layer=um actiontype=$Action filterkey=$uuid $auditParam
add condition field=if_uuid matchtype=equal data=$uuid
add filter

"@
        }
        else {
            Write-Host "`nBlocking all interfaces:" -ForegroundColor Yellow
            foreach ($interface in $RpcInterfaces.Keys) {
                $uuid = $RpcInterfaces[$interface].UUID
                Write-Host "    - $interface ($($RpcInterfaces[$interface].Description))" -ForegroundColor Yellow
                Write-Host "    - UUID: $uuid" -ForegroundColor Yellow
                Write-Host ""
                $filterCommands += @"
add rule layer=um actiontype=block filterkey=$uuid
add condition field=if_uuid matchtype=equal data=$uuid
add filter

"@
            }
        }
        
        $filterCommands | Out-File -FilePath $tempFile -Encoding ASCII
        $result = netsh -f $tempFile 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully Set $($Action) on RPC interface(s).`n" -ForegroundColor Green
        } else {
            throw $result
        }
    }
    catch {
        Write-Error "Failed to $Action RPC interfaces: $_"
    }
    finally {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

function Get-BlockedInterfaces {
    [CmdletBinding()]
    param()
    
    try {
        $filters = netsh rpc filter show filter
        $blockedInterfaces = @()
        
        # Process each line of output
        $currentFilter = $null
        $currentAction = $null
        $currentFilterId = $null
        
        $filters | ForEach-Object {
            if ($_ -match 'filterKey: ([a-f0-9-]{36})') {
                $currentFilter = $matches[1]
            }
            elseif ($_ -match 'filterId: (0x[a-f0-9]+)') {
                $currentFilterId = $matches[1]
            }
            elseif ($_ -match 'action\.type: (\w+)') {
                $currentAction = $matches[1]
                $interface = $RpcInterfaces.GetEnumerator() | Where-Object { 
                    $_.Value.UUID -eq $currentFilter
                }
                if ($interface) {
                    # Convert hex filter ID to decimal
                    $decimalId = [Convert]::ToInt32($currentFilterId, 16)
                    $blockedInterfaces += @{
                        Name = $interface.Key
                        Description = $interface.Value.Description
                        UUID = $interface.Value.UUID
                        Action = $currentAction
                        FilterId = "$currentFilterId ($decimalId)"
                    }
                }
            }
        }
        
        if ($blockedInterfaces.Count -eq 0) {
            Write-Host "`nNo RPC interfaces are currently blocked.`n" -ForegroundColor Yellow
        } else {
            Write-Host "`nCurrently configured RPC interfaces:" -ForegroundColor Green
            $blockedInterfaces | ForEach-Object {
                Write-Host "    - $($_.Name) ($($_.Description))" -ForegroundColor Green
                Write-Host "    - UUID: $($_.UUID)" -ForegroundColor Green
                Write-Host "    - Action: $($_.Action)" -ForegroundColor Green
                Write-Host "    - Filter ID: $($_.FilterId)" -ForegroundColor Green
                Write-Host ""
            }
        }
        
        return
    }
    catch {
        Write-Error "Failed to retrieve RPC filters: $_"
        return $null
    }
}

function Remove-AllRpcFilters {
    [CmdletBinding()]
    param()
    
    try {
        $result = netsh rpc filter delete filter all 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "All RPC filters removed successfully." -ForegroundColor Green
        } else {
            throw $result
        }
    }
    catch {
        Write-Error "Failed to remove RPC filters: $_"
    }
}

# Help text and command execution after function definitions
if ($help) {
    Write-Host @"
RPC Filter Management Script
---------------------------
This script helps manage RPC interface filters for security hardening.

Commands:
    -b, -block   : Block RPC interfaces (use with -i to block specific interface)
    -a, -allow  : Permit RPC interfaces (must be used with -i)
    -l, -list    : Show currently blocked interfaces
    -r, -remove  : Removes all RPC filters !!!Use with caution!!!
    -i           : Specify interface to block/permit (use with -b or -a)
    -h, -help    : Show this help

Available Interfaces:
$(foreach ($key in $RpcInterfaces.Keys) {
    "`n    $key".PadRight(15) + ": $($RpcInterfaces[$key].Description)".PadRight(35) + "[$($RpcInterfaces[$key].UUID)]"
})

Usage:
    ./Coercion-Filters.ps1 -h                 : Show this help
    ./Coercion-Filters.ps1 -b                 : Block all interfaces
    ./Coercion-Filters.ps1 -b -i MS-RPRN     : Block specific interface
    ./Coercion-Filters.ps1 -a -i MS-RPRN     : Set Permit on specific interface and enable auditing.
    ./Coercion-Filters.ps1 -l                 : List blocked interfaces
    ./Coercion-Filters.ps1 -r                 : Remove all filters
"@ -ForegroundColor Cyan
    return
}

# Execute command based on parameters
if ($block) { 
    Set-RpcInterfaceFilter -InterfaceName $interface -Action 'block'
}
if ($permit) {
    if (-not $interface) {
        Write-Error "The -permit option requires specifying an interface with -i"
        return
    }
    Set-RpcInterfaceFilter -InterfaceName $interface -Action 'permit'
}
if ($list) { 
    Get-BlockedInterfaces 
}
if ($remove) { 
    Remove-AllRpcFilters 
}

# Module export at the end
if ($MyInvocation.Line -match 'Import-Module') {
    Export-ModuleMember -Function Set-RpcInterfaceFilter, Get-BlockedInterfaces, Remove-AllRpcFilters
}

<#
.EXAMPLE
    # Block all critical RPC interfaces
    Set-RpcInterfaceFilter

    # Check which interfaces are blocked
    Get-BlockedInterfaces

    # Remove all filters
    Remove-AllRpcFilters
#>
