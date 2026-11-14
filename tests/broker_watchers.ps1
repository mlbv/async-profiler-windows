# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
param([Parameter(Mandatory = $true)][int]$BrokerPid, [switch]$IncludeBootstrap)
$ErrorActionPreference = 'Stop'
$watchers = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $BrokerPid AND Name = 'asprof-helper.exe'" |
    Where-Object { $_.CommandLine -like '*--etw-watch-broker*' } | ForEach-Object { [int]$_.ProcessId })
if ($IncludeBootstrap) {
    $worker = Get-CimInstance Win32_Process -Filter "ProcessId = $BrokerPid"
    $bootstrap = Get-CimInstance Win32_Process -Filter "ProcessId = $($worker.ParentProcessId)"
    if (!$bootstrap -or $bootstrap.Name -ne 'asprof-helper.exe' -or $bootstrap.CommandLine -notlike '*--etw-broker *') { throw 'Expected the private worker bootstrap' }
    ConvertTo-Json -InputObject @{ bootstrap = [int]$bootstrap.ProcessId; watchers = $watchers } -Compress
} else {
    ConvertTo-Json -InputObject $watchers -Compress
}
