<#
.SYNOPSIS
    Unified module for Intune Cosmos DB access management.

.DESCRIPTION
    This module provides comprehensive functionality to:
    1. Query Kusto for Intune inventory details
    2. Generate JIT access commands for Cosmos DB resources
    3. Execute JIT access requests
    4. Manage Azure role assignments for Cosmos DB access

.NOTES
    Module: IntuneCosmosDBAccess
    Author: Uma Parhar
    Version: 1.0.1
#>

# Import required modules and dependencies
#Requires -Version 5.1

# Module variables
$script:ModuleRoot = $PSScriptRoot
$script:KustoDllPath = ""
$script:DefaultKustoCluster = "https://intuneinternal.kusto.windows.net"
$script:DefaultKustoDatabase = "intune"

#region Core Kusto Functions

<#
.SYNOPSIS
    Queries Intune inventory details from Kusto cluster.

.DESCRIPTION
    Executes a Kusto query to retrieve inventory details for specified microservice and scale unit.

.PARAMETER MicroServiceName
    The microservice name to filter by (e.g., "RACerts", "CloudPKI").

.PARAMETER ScaleUnit
    The scale unit to filter by (e.g., "AMSUA0101", "AMSUB0101").

.PARAMETER KustoDllPath
    Path to the Kusto client library DLLs. If you are running on SAW, the DLLs must be signed.

.PARAMETER AuthMethod
    Authentication method: UserPrompt, AzureCLI, or ApplicationCertificate.

.EXAMPLE
    Get-IntuneInventoryDetails -MicroServiceName "RACerts" -ScaleUnit "AMSUA0101"
#>
function Get-IntuneInventoryDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MicroServiceName,

        [Parameter(Mandatory = $true)]
        [string]$ScaleUnit,

        [string]$KustoDllPath = $script:KustoDllPath,

        [ValidateSet("UserPrompt", "AzureCLI", "ApplicationCertificate")]
        [string]$AuthMethod = "UserPrompt",

        [string]$ComponentName = "CosmosDB",

        [string]$ResourceType = "Microsoft.DocumentDB/databaseAccounts"
    )

    try {
        # Check if Kusto configuration is set up
        if ([string]::IsNullOrEmpty($KustoDllPath) -and [string]::IsNullOrEmpty($script:KustoDllPath)) {
            throw "Kusto DLL path not configured. Please run: Set-IntuneKustoConfiguration -KustoDllPath 'C:\path\to\kusto\dlls'"
        }

        # Load Kusto libraries
        Write-Host "Initializing Kusto client..." -ForegroundColor Yellow
        Initialize-KustoClient -DllPath $KustoDllPath
        Write-Host "Kusto DLL Path: $KustoDllPath" -ForegroundColor Gray

        # Build query
            $query = @"
InventoryDetails
| where JobRunId in (GetInventoryLatestRunIdProdPMENew())
| where ScaleUnit =~ "$ScaleUnit"
| where MicroServiceName =~ "$MicroServiceName"
| where ComponentName == "$ComponentName"
| where ResourceType == "$ResourceType"
"@

        # Execute query
        $result = Invoke-KustoQuery -Query $query -AuthMethod $AuthMethod
        Write-Output $result -NoEnumerate

    } catch {
        Write-Error "Failed to get inventory details: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Creates JIT access commands for Cosmos DB resources.

.DESCRIPTION
    Analyzes inventory data and generates the appropriate JIT access commands for CosmosDB resources.
    This function creates the commands but does not execute them.

.PARAMETER InventoryData
    Inventory data from Get-IntuneInventoryDetails or custom DataTable.

.PARAMETER Justification
    Justification text for the access request.

.PARAMETER WorkItemId
    Work item ID for tracking purposes.

.PARAMETER PmeAlias
    PME alias for the request.

.PARAMETER PmeObjectId
    PME ObjectId for the request.

.PARAMETER ExecuteJitAccess
    Actually execute the JIT access requests instead of just generating command strings.

.PARAMETER OutputCommands
    Return generated commands as strings instead of displaying them.

.PARAMETER Environment
    Target environment. Defaults to "Product".

.EXAMPLE
    $inventory = Get-IntuneInventoryDetails -MicroServiceName "RACerts" -ScaleUnit "AMSUA0101"
    New-IntuneCosmosJitAccess -InventoryData $inventory -Justification "Debug CRI" -WorkItemId "12345678" -PmeAlias "umaparhar"
#>
function New-IntuneCosmosJitAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InventoryData,

        [Parameter(Mandatory = $true)]
        [string]$Justification,

        [Parameter(Mandatory = $true)]
        [string]$WorkItemId,

        [Parameter()]
        [string]$PmeAlias,

        [Parameter()]
        [string]$PmeObjectId,

        [string]$Environment = "Product",
        [ValidateSet("ReadOnly", "ReadWrite")]
        [string]$AccessType = "ReadOnly",
        [switch]$ExecuteJitAccess,
        [switch]$ReAuthenticateAfterJit
    )

    try {
        # Handle different input types
        if ($InventoryData -is [System.Data.DataTable]) {
            $dataTable = $InventoryData
        } elseif ($InventoryData -is [System.Object[]] -and $InventoryData[0] -is [System.Data.DataRow]) {
            # If we got an array of DataRows, reconstruct the DataTable
            $dataTable = $InventoryData[0].Table
        } else {
            throw "InventoryData must be a DataTable or array of DataRows from Get-IntuneInventoryDetails"
        }

        if (-not($dataTable.Rows.Count -eq 1)) {
            Write-Warning "Expected exactly one row in inventory data, but found $($dataTable.Rows.Count). Cannot generate JIT access command."
            return
        }

        $cosmosInfo = Get-CosmosDbInfoFromInventory -InventoryRow $dataTable.Rows[0]

        if (-not $cosmosInfo) {
            Write-Warning "No Cosmos DB information found in the provided inventory data."
            return
        }

        if($PmeAlias){
            $command = Build-JitAccessCommand -CosmosInfo $cosmosInfo -Justification $Justification -WorkItemId $WorkItemId -PmeAlias $PmeAlias -Environment $Environment -AccessType $AccessType -ReAuthenticateAfterJit:$ReAuthenticateAfterJit
        }
        else{
            $command = Build-JitAccessCommand -CosmosInfo $cosmosInfo -Justification $Justification -WorkItemId $WorkItemId -PmeObjectId $PmeObjectId -Environment $Environment -AccessType $AccessType -ReAuthenticateAfterJit:$ReAuthenticateAfterJit
        }


        Write-Host "Generated JIT command for: $($cosmosInfo.AccountName)" -ForegroundColor Green
        return $command
    } catch {
        Write-Error "Failed to create JIT access commands: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    End-to-end Cosmos DB access workflow: Query inventory, generate JIT access, and optionally execute role assignments.

.DESCRIPTION
    Complete workflow that:
    1. Queries Kusto for inventory details
    2. Generates JIT access commands
    3. Optionally executes the JIT request
    4. Optionally performs Azure role assignment once JIT request is granted.

.PARAMETER MicroServiceName
    The microservice name to process.

.PARAMETER ScaleUnit
    The scale unit to process.

.PARAMETER Justification
    Justification for access request.

.PARAMETER AccessType
    Type of access to request: ReadOnly or ReadWrite. Defaults to ReadOnly.

.PARAMETER ExecuteJitAccess
    Actually execute the JIT access commands (not just display them).

.PARAMETER AssignAzureRoles
    Perform Azure role assignments after JIT access is granted.

.PARAMETER WorkItemId
    Work item ID for the JIT request.

.PARAMETER ReAuthenticateAfterJit
    Clear Azure account cache and re-authenticate after JIT approval.

.EXAMPLE
    Invoke-IntuneE2ECosmosAccess -MicroServiceName "RACerts" -ScaleUnit "AMSUA0101" -Justification "CRI debugging" -WorkItemId "12345678" -PmeAlias "umaparhar"

.EXAMPLE
    Invoke-IntuneE2ECosmosAccess -MicroServiceName "RACerts" -ScaleUnit "AMSUA0101" -Justification "CRI debugging" -WorkItemId "12345678" -PmeAlias "umaparhar" -ExecuteJitAccess -AssignAzureRoles

.EXAMPLE
    Invoke-IntuneE2ECosmosAccess -MicroServiceName "CloudPKI" -ScaleUnit "AMSUB0101" -Justification "CRI debugging" -WorkItemId "12345678" -PmeAlias "umaparhar" -AccessType "ReadWrite" -ExecuteJitAccess -AssignAzureRoles

.EXAMPLE
    Invoke-IntuneE2ECosmosAccess -MicroServiceName "CloudPKI" -ScaleUnit "AMSUB0101" -Justification "CRI debugging" -WorkItemId "12345678" -PmeAlias "umaparhar" -ExecuteJitAccess
#>
function Invoke-IntuneE2ECosmosAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MicroServiceName,

        [Parameter(Mandatory = $true)]
        [string]$ScaleUnit,

        [Parameter(Mandatory = $true)]
        [string]$Justification,

        [Parameter(Mandatory = $true)]
        [string]$WorkItemId,

        [Parameter()]
        [string]$PmeObjectId,

        [Parameter()]
        [string]$PmeAlias,

        [ValidateSet("ReadOnly", "ReadWrite")]
        [string]$AccessType = "ReadOnly",
        [switch]$ExecuteJitAccess,
        [switch]$AssignAzureRoles,
        [switch]$ReAuthenticateAfterJit
    )

    try {
        Write-Host "Executing E2E Cosmos DB Access Workflow.." -ForegroundColor Cyan
        Write-Host "MicroService: $MicroServiceName" -ForegroundColor White
        Write-Host "ScaleUnit: $ScaleUnit" -ForegroundColor White
        Write-Host "Access Type: $AccessType" -ForegroundColor White
        Write-Host "Justification: $Justification" -ForegroundColor White
        Write-Host ""

        # Query inventory
        Write-Host "Querying Intune inventory..."
        $inventoryData = Get-IntuneInventoryDetails -MicroServiceName $MicroServiceName -ScaleUnit $ScaleUnit

        if ($inventoryData.Rows.Count -eq 0) {
            Write-Warning "No inventory data found for MicroService '$MicroServiceName' and ScaleUnit '$ScaleUnit'"
            return
        }

        # Generate JIT commands
        Write-Host "Generating JIT request command..."
        if ($PmeAlias) {
            $jitCommand = New-IntuneCosmosJitAccess -InventoryData $inventoryData -Justification $Justification -WorkItemId $WorkItemId -PmeAlias $PmeAlias -AccessType $AccessType -ReAuthenticateAfterJit:$ReAuthenticateAfterJit
        }
        else{
            if (-not $PmeObjectId) {
                Write-Warning "PME Object ID / PME alias not provided. Cannot generate JIT access command."
                return
            }
            $jitCommand = New-IntuneCosmosJitAccess -InventoryData $inventoryData -Justification $Justification -WorkItemId $WorkItemId -PmeObjectId $PmeObjectId -AccessType $AccessType -ReAuthenticateAfterJit:$ReAuthenticateAfterJit
        }
        if (-not($jitCommand.Count -eq 1)) {
            Write-Warning "Generated $($jitCommands.Count) JIT access command(s). Expected One." -ForegroundColor Green
            return
        }

        # Execute JIT access if requested
        if ($ExecuteJitAccess) {
            Write-Host "Executing JIT access requests..." -ForegroundColor Yellow

            # Determine if we should skip role assignment in the Get-CosmosDB functions
            $skipRoleAssignment = -not $AssignAzureRoles

            $jitResults = @()
            try {
                # Add SkipRoleAssignment flag if we're handling roles separately
                if ($skipRoleAssignment) {
                    $jitCommand += " -SkipRoleAssignment"
                }

                Write-Host "Executing: $jitCommand"

                $result = Invoke-Expression $jitCommand

                # Check if the result indicates success or failure
                if ($result -and $result -ne $null -and $result.Success -eq $true) {
                    $jitResults += @{
                        Command = $jitCommand
                        Success = $true
                        Result = $result
                    }
                    Write-Host "JIT request submitted successfully" -ForegroundColor Green
                } else {
                    $jitResults += @{
                        Command = $jitCommand
                        Success = $false
                        Error = "JIT request returned null or failed"
                    }
                    Write-Warning "JIT request failed."
                    #throw
                }
            } catch {
                $jitResults += @{
                    Command = $jitCommand
                    Success = $false
                    Error = $_.Exception.Message
                }
                Write-Warning "JIT request failed: $($_.Exception.Message)"
                throw
            }

        } else {
            Write-Host "JIT command generated (not executed): $($jitCommand)"
            Write-Host ""
            Write-Host "To execute these commands, add -ExecuteJitAccess parameter."
        }

    } catch {
        Write-Error "E2E workflow failed: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Sets configuration for the Kusto connection and module defaults.

.PARAMETER KustoDllPath
    Path to Kusto client library DLLs.

.PARAMETER DefaultCluster
    Default Kusto cluster URL.

.PARAMETER DefaultDatabase
    Default Kusto database name.

.EXAMPLE
    Set-IntuneKustoConfiguration -KustoDllPath "C:\Tools\Kusto\net472" -DefaultCluster "https://mycompany.kusto.windows.net"
#>
function Set-IntuneKustoConfiguration {
    [CmdletBinding()]
    param(
        [string]$KustoDllPath,
        [string]$DefaultCluster,
        [string]$DefaultDatabase
    )

    if ($KustoDllPath) {
        $script:KustoDllPath = $KustoDllPath
        Write-Host "Kusto DLL path set to: $KustoDllPath" -ForegroundColor Green
    }

    if ($DefaultCluster) {
        $script:DefaultKustoCluster = $DefaultCluster
        Write-Host "Default cluster set to: $DefaultCluster" -ForegroundColor Green
    }

    if ($DefaultDatabase) {
        $script:DefaultKustoDatabase = $DefaultDatabase
        Write-Host "Default database set to: $DefaultDatabase" -ForegroundColor Green
    }
}

#endregion

#region Helper Functions

function Initialize-KustoClient {
    param([string]$DllPath)

    if ([string]::IsNullOrEmpty($DllPath) -and [string]::IsNullOrEmpty($script:KustoDllPath)) {
        throw "Kusto DLL path not configured. Use Set-IntuneKustoConfiguration or provide -KustoDllPath parameter."
    }

    $pathToUse = if ($DllPath) { $DllPath } else { $script:KustoDllPath }

    # Load Kusto libraries
    $loadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $kustoDataAssembly = $loadedAssemblies | Where-Object { $_.GetName().Name -eq "Kusto.Data" }

    if ($kustoDataAssembly) {
        Write-Verbose "Kusto.Data assembly already loaded (Version: $($kustoDataAssembly.GetName().Version))"
    } else {
        $kustoDataDll = Join-Path $pathToUse "Kusto.Data.dll"
        if (-not (Test-Path $kustoDataDll)) {
            throw "Kusto.Data.dll not found at: $kustoDataDll"
        }
        [System.Reflection.Assembly]::LoadFrom($kustoDataDll) | Out-Null
        Write-Verbose "Successfully loaded Kusto client libraries from: $pathToUse"
    }
}

function Invoke-KustoQuery {
    param(
        [string]$Query,
        [string]$AuthMethod = "UserPrompt"
    )

    # Create connection string based on auth method
    switch ($AuthMethod) {
        "UserPrompt" {
            $connectionString = "$script:DefaultKustoCluster;Fed=true;AuthorityId=common"
        }
        "AzureCLI" {
            try {
                $azAccount = az account show 2>$null | ConvertFrom-Json
                if ($azAccount) {
                    $connectionString = "$script:DefaultKustoCluster;Fed=true;AuthorityId=$($azAccount.tenantId)"
                } else {
                    throw "Not logged in to Azure CLI"
                }
            }
            catch {
                throw "Azure CLI authentication failed. Please run 'az login' first."
            }
        }
        "ApplicationCertificate" {
            throw "ApplicationCertificate authentication not yet implemented in module version"
        }
    }

    $kcsb = New-Object Kusto.Data.KustoConnectionStringBuilder($connectionString, $script:DefaultKustoDatabase)
    $queryProvider = [Kusto.Data.Net.Client.KustoClientFactory]::CreateCslQueryProvider($kcsb)

    $crp = New-Object Kusto.Data.Common.ClientRequestProperties
    $crp.ClientRequestId = "IntuneCosmosAccess.ExecuteQuery." + [Guid]::NewGuid().ToString()
    $crp.SetOption([Kusto.Data.Common.ClientRequestProperties]::OptionServerTimeout, [TimeSpan]::FromSeconds(300))

    $reader = $queryProvider.ExecuteQuery($Query, $crp)
    $dataSet = [Kusto.Cloud.Platform.Data.ExtendedDataReader]::ToDataSet($reader)
    $dataTable = $dataSet.Tables[0]

    # Force PowerShell to preserve the DataTable structure using Write-Output -NoEnumerate
    Write-Output $dataTable -NoEnumerate
}

function ConvertFrom-DataTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.DataTable]$DataTable
    )

    $objects = @()
    foreach ($row in $DataTable.Rows) {
        $obj = New-Object PSObject
        foreach ($column in $DataTable.Columns) {
            $obj | Add-Member -Type NoteProperty -Name $column.ColumnName -Value $row[$column.ColumnName]
        }
        $objects += $obj
    }
    return $objects
}

function ConvertTo-DataTable {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [PSObject[]]$InputObject
    )

    begin {
        $dataTable = New-Object System.Data.DataTable
        $columnsCreated = $false
    }

    process {
        foreach ($object in $InputObject) {
            if (-not $columnsCreated) {
                # Create columns based on the first object
                $object.PSObject.Properties | ForEach-Object {
                    $column = New-Object System.Data.DataColumn($_.Name, [object])
                    $dataTable.Columns.Add($column)
                }
                $columnsCreated = $true
            }

            # Add row
            $row = $dataTable.NewRow()
            $object.PSObject.Properties | ForEach-Object {
                $row[$_.Name] = if ($null -eq $_.Value) { [DBNull]::Value } else { $_.Value }
            }
            $dataTable.Rows.Add($row)
        }
    }

    end {
        return $dataTable
    }
}

function Get-CosmosDbInfoFromInventory {
    param($InventoryRow)

    $resourceType = $InventoryRow["ResourceType"]
    $resourceName = $InventoryRow["ResourceName"]
    $resourceId = $InventoryRow["ResourceId"]
    $subscriptionId = $InventoryRow["SubscriptionId"]
    $resourceGroupName = $InventoryRow["ResourceGroupName"]

    # Determine if this is a Cosmos DB resource
    $cosmosDbAccountName = ""

    if ($resourceType -eq "Microsoft.DocumentDB/databaseAccounts") {
        $cosmosDbAccountName = $resourceName
    } elseif ($resourceId -match 'Microsoft\.DocumentDB/databaseAccounts/([^/]+)') {
        $cosmosDbAccountName = $matches[1]
    } elseif ($resourceName -match "cosdb|cosmos") {
        $cosmosDbAccountName = $resourceName
    } else {
        Write-Verbose "Resource not identified as Cosmos DB: $resourceName (Type: $resourceType)"
        return $null
    }

    return @{
        AccountName = $cosmosDbAccountName
        SubscriptionId = $subscriptionId
        ResourceGroupName = $resourceGroupName
        ResourceId = $resourceId
    }
}

function Build-JitAccessCommand {
    param(
        $CosmosInfo,
        [Parameter(Mandatory = $true)]
        [string]$Justification,
        [Parameter(Mandatory = $true)]
        [string]$WorkItemId,
        [Parameter()]
        [string]$PmeAlias,
        [Parameter()]
        [string]$PmeObjectId,
        [string]$Environment = "Product",
        [ValidateSet("ReadOnly", "ReadWrite")]
        [string]$AccessType = "ReadOnly",
        [switch]$ReAuthenticateAfterJit
    )

    $functionName = if ($AccessType -eq "ReadWrite") { "Get-CosmosDBWriteAccess" } else { "Get-CosmosDBReadAccess" }
    $reAuthFlag = if ($ReAuthenticateAfterJit) { "-ReAuthenticateAfterJit" } else { "" }
    if ($PmeObjectId){
        return "$functionName -SubscriptionId $($CosmosInfo.SubscriptionId) -CosmosDbAccountName $($CosmosInfo.AccountName) -ResourceGroupName $($CosmosInfo.ResourceGroupName) -Justification `"$Justification`" -Env `"$Environment`" -Src Other -Wid $WorkItemId -PmeObjectId $PmeObjectId $reAuthFlag"
    }
    return "$functionName -SubscriptionId $($CosmosInfo.SubscriptionId) -CosmosDbAccountName $($CosmosInfo.AccountName) -ResourceGroupName $($CosmosInfo.ResourceGroupName) -Justification `"$Justification`" -Env `"$Environment`" -Src Other -Wid $WorkItemId -PmeAlias $PmeAlias $reAuthFlag"
}

function Wait-ForJitApproval {
    param([int]$TimeoutMinutes)

    Write-Host "Waiting for JIT approval (timeout: $TimeoutMinutes minutes)..."
    Write-Host "Note: This is a placeholder implementation. In real scenarios, this would:"
    Write-Host "  1. Check approval status via API calls"
    Write-Host "  2. Poll for status changes"
    Write-Host "  3. Return when approved or timeout"

    # Placeholder implementation
    Start-Sleep -Seconds 5
    Write-Host "Approval check completed (simulated)." -ForegroundColor Green
    return $true
}

#endregion

#region CosmosDB Access Functions (from IntuneCosmosAccess.psm1)

# Helper function to check if Azure CLI is installed
function Test-AzCLI {
    if (-not (Get-Command "az" -ErrorAction SilentlyContinue)) {
        Write-Error "Azure CLI (az) is not installed on this machine."
        return $false
    }
    return $true
}

# Helper function to set the Azure subscription
function Set-AzSubscription {
    param (
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    az account set -s $SubscriptionId
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to set the Azure subscription. Please check the Subscription ID and try again."
        return $false
    }
    return $true
}

# Helper function to retrieve PME Object ID
function Get-PmeObjectId {
    param (
        [Parameter(Mandatory)]
        [string]$pmeAlias
    )
    Write-Host "Attempting to retrieve the PME Object ID using the alias: $pmeAlias"
    $pmeObjectIdResult = az ad user list --query "[?userPrincipalName=='$pmeAlias@pme.gbl.msidentity.com'].id" --output tsv
    if ($LASTEXITCODE -eq 0 -and $pmeObjectIdResult) {
        $pmeObjectId = $pmeObjectIdResult.Trim()
        Write-Host "Successfully retrieved PME Object ID: $pmeObjectId"
    }
    else {
        Write-Host "Failed to retrieve PME Object ID using the alias: $pmeAlias" -ForegroundColor Red
        Write-Host "Please manually retrieve your PME Object ID by following these steps:"
        Write-Host "1. Navigate to Microsoft Entra ID -> Manage -> Users."
        Write-Host "2. Look up your alias ($pmeAlias)."
        Write-Host "3. Go to the Overview section, and note the Object ID."
        $pmeObjectId = Read-Host "Enter your PME Object ID"
    }
    # Return the PME Object ID
    return $pmeObjectId
}

function Check-JITShellInstallation {
    # Check if the environment variable dstsFederationNamespace is set to "pme.gbl.msidentity.com".
    # Check if the JITShell module is imported in the current session
    $imported = Get-Module -Name JITShell -ErrorAction SilentlyContinue
    if ($imported) {
        Write-Host "JITShell module is imported in this session." -ForegroundColor Green
        # Check if the environment variable dstsFederationNamespace is set to "pme.gbl.msidentity.com".
        if ($env:dstsFederationNamespace -eq "pme.gbl.msidentity.com") {
            Write-Host "PME env set"
        }
        else {
            Write-Host "PME not set, setting dstsFederationNamespace to 'pme.gbl.msidentity.com'"
            $env:dstsFederationNamespace = "pme.gbl.msidentity.com"
        }
        return $true
    }
    # Check if the JITShell module is installed/available on the system
    $available = Get-Module -ListAvailable -Name JITShell | Select-Object -First 1
    if ($available) {
        Write-Host "JITShell module is installed but not imported. Importing now..."
        try {
            Import-Module JITShell -ErrorAction Stop
            Write-Host "JITShell module imported successfully." -ForegroundColor Green
            if ($env:dstsFederationNamespace -eq "pme.gbl.msidentity.com") {
                Write-Host "PME env set"
            }
            else {
                Write-Host "PME not set, setting dstsFederationNamespace to 'pme.gbl.msidentity.com'"
                $env:dstsFederationNamespace = "pme.gbl.msidentity.com"
            }
            return $true
        }
        catch {
            Write-Error "Failed to import the JITShell module: $_"
            return $false
        }
    }
    else {
        Write-Error "JITShell module is not installed on this system. Attempting to install and import..."
        # Call Init-JITShell with no arguments (or provide a path if needed)
        Init-JITShell
        # After attempting install, check again
        $importedAfter = Get-Module -Name JITShell -ErrorAction SilentlyContinue
        if ($importedAfter) {
            Write-Host "JITShell module imported successfully after installation." -ForegroundColor Green
            return $true
        }
        else {
            Write-Error "Failed to install or import the JITShell module."
            return $false
        }
    }
}

function Init-JITShell {
    param (
        [string]$sawPSModulesPath
    )
    # If the sawPSModulesPath parameter is empty, set it to the default path in the current directory.
    if ($sawPSModulesPath -eq "") {
        $currentDirectory = (Get-Location).Path
        $sawPSModulesPath = $currentDirectory + '\SAWPSModulePath\'
    }
    # Check if the specified path exists. If not, output an error and return.
    if ((Test-Path $sawPSModulesPath) -eq $false) {
        Write-Error "Failed to find SAWPSModulePath"
        return
    }
    $jitModulesPath = $sawPSModulesPath + '\JITShell'
    # Check if the JITShell module path exists.
    if (Test-Path $jitModulesPath) {
        Write-Host "Found JITShell, initialized JITShell"
        # Import the JITShell module if it is found.
        Import-Module -Name JITShell
    }
    else {
        Write-Host "JITShell is not installed, Importing"
        # If the JITShell module is not found, save and import it
        Save-Module -Name JITShell -Path $sawPSModulesPath -Force
        Import-Module -Name JITShell
    }
    # Check if the environment variable dstsFederationNamespace is set to "pme.gbl.msidentity.com".
    if ($env:dstsFederationNamespace -eq "pme.gbl.msidentity.com") {
        Write-Host "PME env set"
    }
    else {
        Write-Host "PME not set, setting dstsFederationNamespace to 'pme.gbl.msidentity.com'"
        $env:dstsFederationNamespace = "pme.gbl.msidentity.com"
    }
}

function Request-JITAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Justification,
        [Parameter(Mandatory)]
        [string]$Env,
        [Parameter(Mandatory)]
        [string]$Src,
        [Parameter(Mandatory)]
        [string]$Wid,
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$ResourceName
    )
    if (-not (Check-JITShellInstallation)) {
        Write-Error "JITShell module is not available. Cannot proceed with JIT request."
        return $null
    }
    $propertyBag = @{
        SubscriptionID = $SubscriptionId
        ResourceName   = $ResourceName
    }
    $command = @(
        "New-JITRequest",
        "-env `"$Env`"",
        "-src `"$Src`"",
        "-wid `"$Wid`"",
        "-Justification `"$Justification`"",
        "-rtype `"Self-Service`"",
        "-SelfServiceType `"Azure cosmos Rbac`"",
        "-AccessLevel `"DocumentDB Account Contributor`"",
        "-ver `"2015-09-07.1.0`"",
        "-PropertyBag `"$propertyBag`""
    ) -join " "
    Write-Host "Running the following command:" -ForegroundColor Green
    Write-Host $command
    try {
        $cmd = New-JITRequest -env $Env -src $Src -wid $Wid -Justification $Justification -rtype "Self-Service" -SelfServiceType "Azure Cosmos Rbac" -AccessLevel "DocumentDB Account Contributor" -ver "2015-09-07.1.0" -PropertyBag $propertyBag
        return $cmd
    }
    catch {
        Write-Error "Failed to submit JIT request: $_"
        return $null
    }
}

# Cmdlet: Get-CosmosDBReadAccess
function Get-CosmosDBReadAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$CosmosDbAccountName,
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        [Parameter()]
        [string]$PmeAlias,
        [Parameter()]
        [string]$PmeObjectId,
        # JIT Access parameters
        [Parameter(Mandatory)]
        [string]$Justification,
        [Parameter(Mandatory)]
        [string]$Env,
        [Parameter(Mandatory)]
        [string]$Src,
        [Parameter(Mandatory)]
        [string]$Wid,
        # Skip role assignment flag
        [switch]$SkipRoleAssignment,
        [switch]$ReAuthenticateAfterJit
    )

    try {
        # Request JIT Access and capture the request object
        $jitResult = Request-JITAccess -Justification $Justification -Env $Env -Src $Src -Wid $Wid -SubscriptionId $SubscriptionId -ResourceName $CosmosDbAccountName
        if (-not $jitResult) {
            Write-Error "Failed to submit JIT request."
            return @{
                Success = $false
                Error = "Failed to submit JIT request"
                AccountName = $CosmosDbAccountName
            }
        }

        # Extract the RequestId from the JIT result
        $requestId = $null
        try {
            if ($jitResult.RequestId) {
                $requestId = $jitResult.RequestId
            }
            elseif ($jitResult | Get-Member -Name id) {
                $requestId = $jitResult.id
            }
            elseif ($jitResult -is [string]) {
                $requestId = $jitResult
            }
        }
        catch {
            Write-Error "Could not extract RequestId from JIT request result."
            return @{
                Success = $false
                Error = "Could not extract RequestId from JIT request result"
                AccountName = $CosmosDbAccountName
            }
        }

        if (-not $requestId) {
            Write-Error "No RequestId found in JIT request result."
            return @{
                Success = $false
                Error = "No RequestId found in JIT request result"
                AccountName = $CosmosDbAccountName
            }
        }

        # Poll for JIT approval
        $maxAttempts = 30
        $attempt = 0
        $approved = $false
        $pollIntervalSeconds = 60
        Write-Host "Polling for JIT access approval (RequestId: $requestId)..." -ForegroundColor Yellow
        while ($attempt -lt $maxAttempts) {
            $jitStatus = $null
            try {
                $jitStatus = Get-JITRequest -env $Env -RequestId $requestId -ver "2015-09-07.1.0" -includeStateTransition
            }
            catch {
                Write-Warning "Failed to get JIT request status. Retrying..."
            }
            if ($jitStatus -and ($jitStatus.Approver -or $jitStatus.StateTransitionRecords.phase[0] -eq 'Granted')) {
                Write-Host "JIT access approved!" -ForegroundColor Green
                $approved = $true
                if ($ReAuthenticateAfterJit) {
                        Write-Host "Re-authenticating with Azure after JIT approval..." -ForegroundColor Yellow
                        try {
                            az account clear
                            az login
                        }
                        catch {
                            Write-Warning "Failed to re-authenticate with Azure: $($_.Exception.Message)"
                        }
                    }
                break
            }
            else {
                Write-Host "JIT access not yet approved. Waiting $pollIntervalSeconds seconds before retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds $pollIntervalSeconds
                $attempt++
            }
        }

        if (-not $approved) {
            Write-Error "JIT access was not approved within the expected time window."
            return @{
                Success = $false
                Error = "JIT access was not approved within the expected time window"
                AccountName = $CosmosDbAccountName
                JitApproved = $false
            }
        }

        # Skip role assignment if flag is set
        if ($SkipRoleAssignment) {
            Write-Host "JIT access approved. Skipping role assignment as requested." -ForegroundColor Green
            return @{
                Success = $true
                AccountName = $CosmosDbAccountName
                JitApproved = $true
                RoleAssignmentSkipped = $true
            }
        }

        if (-not (Test-AzCLI)) {
            return @{
                Success = $false
                Error = "Azure CLI not available"
                AccountName = $CosmosDbAccountName
                JitApproved = $true
            }
        }

        if (-not (Set-AzSubscription -SubscriptionId $SubscriptionId)) {
            return @{
                Success = $false
                Error = "Failed to set Azure subscription"
                AccountName = $CosmosDbAccountName
                JitApproved = $true
            }
        }

        if ($PmeObjectId) {
            try {
                [guid]::Parse($PmeObjectId) | Out-Null
            }
            catch {
                Write-Error "The provided PmeObjectId is not a valid GUID."
                return @{
                    Success = $false
                    Error = "The provided PmeObjectId is not a valid GUID"
                    AccountName = $CosmosDbAccountName
                    JitApproved = $true
                }
            }
        }

        # Use the provided PME Object ID or retrieve it using Get-PmeObjectId
        if (-not $PmeObjectId) {
            if (-not $PmeAlias) {
                Write-Error "Either PmeAlias or PmeObjectId must be provided."
                return @{
                    Success = $false
                    Error = "Either PmeAlias or PmeObjectId must be provided"
                    AccountName = $CosmosDbAccountName
                    JitApproved = $true
                }
            }
            $PmeObjectId = Get-PmeObjectId -PmeAlias $PmeAlias
            if (-not $PmeObjectId) {
                return @{
                    Success = $false
                    Error = "Failed to get PME Object ID"
                    AccountName = $CosmosDbAccountName
                    JitApproved = $true
                }
            }
        }

        $command = @(
            "az cosmosdb sql role assignment create",
            "--account-name $CosmosDbAccountName",
            "--principal-id $PmeObjectId",
            "--resource-group $ResourceGroupName",
            "--scope '/'",
            "--role-definition-id 00000000-0000-0000-0000-000000000001" # Read-only role ID
        ) -join " "

        Write-Host "Running the following command:" -ForegroundColor Green
        Write-Host $command
        $output = Invoke-Expression $command

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Command executed successfully." -ForegroundColor Green
            # Extract and print the role assignment ID
            $roleAssignmentId = $output | ConvertFrom-Json | Select-Object -ExpandProperty id
            Write-Host "Role Assignment ID: $roleAssignmentId" -ForegroundColor Cyan
            return @{
                Success = $true
                AccountName = $CosmosDbAccountName
                JitApproved = $true
                RoleAssigned = $true
                RoleAssignmentId = $roleAssignmentId
            }
        }
        else {
            Write-Error "Command failed."
            return @{
                Success = $false
                Error = "Role assignment command failed"
                AccountName = $CosmosDbAccountName
                JitApproved = $true
                RoleAssigned = $false
            }
        }
    }
    catch {
        Write-Error "Unexpected error in Get-CosmosDBReadAccess: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = "Unexpected error: $($_.Exception.Message)"
            AccountName = $CosmosDbAccountName
        }
    }
}

# Cmdlet: Get-CosmosDBWriteAccess
function Get-CosmosDBWriteAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$CosmosDbAccountName,
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        [Parameter()]
        [string]$PmeAlias,
        [Parameter()]
        [string]$PmeObjectId,
        # JIT Access parameters
        [Parameter(Mandatory)]
        [string]$Justification,
        [Parameter(Mandatory)]
        [string]$Env,
        [Parameter(Mandatory)]
        [string]$Src,
        [Parameter(Mandatory)]
        [string]$Wid,
        [switch]$SkipRoleAssignment,
        [switch]$ReAuthenticateAfterJit
    )

    try {
        # Request JIT Access and capture the request object
        $jitResult = Request-JITAccess -Justification $Justification -Env $Env -Src $Src -Wid $Wid -SubscriptionId $SubscriptionId -ResourceName $CosmosDbAccountName
        if (-not $jitResult) {
            Write-Error "Failed to submit JIT request."
            return @{
                Success = $false
                Error = "Failed to submit JIT request"
                AccountName = $CosmosDbAccountName
            }
        }

        # Extract the RequestId from the JIT result
        $requestId = $null
        try {
            if ($jitResult.RequestId) {
                $requestId = $jitResult.RequestId
            }
            elseif ($jitResult | Get-Member -Name id) {
                $requestId = $jitResult.id
            }
            elseif ($jitResult -is [string]) {
                $requestId = $jitResult
            }
        }
        catch {
            Write-Error "Could not extract RequestId from JIT request result."
            return @{
                Success = $false
                Error = "Could not extract RequestId from JIT request result"
                AccountName = $CosmosDbAccountName
            }
        }

        if (-not $requestId) {
            Write-Error "No RequestId found in JIT request result."
            return @{
                Success = $false
                Error = "No RequestId found in JIT request result"
                AccountName = $CosmosDbAccountName
            }
        }

        # Poll for JIT approval
        $maxAttempts = 30
        $attempt = 0
        $approved = $false
        $pollIntervalSeconds = 60
        Write-Host "Polling for JIT access approval (RequestId: $requestId)..." -ForegroundColor Yellow
        while ($attempt -lt $maxAttempts) {
            $jitStatus = $null
            try {
                $jitStatus = Get-JITRequest -env $Env -RequestId $requestId -ver "2015-09-07.1.0" -includeStateTransition
            }
            catch {
                Write-Warning "Failed to get JIT request status. Retrying..."
            }
            if ($jitStatus -and ($jitStatus.Approver -or $jitStatus.StateTransitionRecords.phase[0] -eq 'Granted')) {
                Write-Host "JIT access approved!" -ForegroundColor Green
                $approved = $true
                if ($ReAuthenticateAfterJit) {
                        Write-Host "Re-authenticating with Azure after JIT approval..." -ForegroundColor Yellow
                        try {
                            az account clear
                            az login
                        }
                        catch {
                            Write-Warning "Failed to re-authenticate with Azure: $($_.Exception.Message)"
                        }
                    }
                break
            }
            else {
                Write-Host "JIT access not yet approved. Waiting $pollIntervalSeconds seconds before retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds $pollIntervalSeconds
                $attempt++
            }
        }

        if (-not $approved) {
            Write-Error "JIT access was not approved within the expected time window."
            return @{
                Success = $false
                Error = "JIT access was not approved within the expected time window"
                AccountName = $CosmosDbAccountName
                JitApproved = $false
            }
        }

        # Skip role assignment if flag is set
        if ($SkipRoleAssignment) {
            Write-Host "JIT access approved. Skipping role assignment as requested." -ForegroundColor Green
            return @{
                Success = $true
                AccountName = $CosmosDbAccountName
                JitApproved = $true
                RoleAssignmentSkipped = $true
            }
        }

        if (-not (Test-AzCLI)) {
            return @{
                Success = $false
                Error = "Azure CLI not available"
                AccountName = $CosmosDbAccountName
                JitApproved = $true
            }
        }

        if (-not (Set-AzSubscription -SubscriptionId $SubscriptionId)) {
            return @{
                Success = $false
                Error = "Failed to set Azure subscription"
                AccountName = $CosmosDbAccountName
                JitApproved = $true
            }
        }

        if ($PmeObjectId) {
            try {
                [guid]::Parse($PmeObjectId) | Out-Null
            }
            catch {
                Write-Error "The provided PmeObjectId is not a valid GUID."
                return @{
                    Success = $false
                    Error = "The provided PmeObjectId is not a valid GUID"
                    AccountName = $CosmosDbAccountName
                    JitApproved = $true
                }
            }
        }

        # Use the provided PME Object ID or retrieve it using Get-PmeObjectId
        if (-not $PmeObjectId) {
            if (-not $PmeAlias) {
                Write-Error "Either PmeAlias or PmeObjectId must be provided."
                return @{
                    Success = $false
                    Error = "Either PmeAlias or PmeObjectId must be provided"
                    AccountName = $CosmosDbAccountName
                    JitApproved = $true
                }
            }
            $PmeObjectId = Get-PmeObjectId -PmeAlias $PmeAlias
            if (-not $PmeObjectId) {
                return @{
                    Success = $false
                    Error = "Failed to get PME Object ID"
                    AccountName = $CosmosDbAccountName
                    JitApproved = $true
                }
            }
        }

        $command = @(
            "az cosmosdb sql role assignment create",
            "--account-name $CosmosDbAccountName",
            "--principal-id $PmeObjectId",
            "--resource-group $ResourceGroupName",
            "--scope '/'",
            "--role-definition-id 00000000-0000-0000-0000-000000000002" # Read-Write role ID
        ) -join " "

        Write-Host "Running the following command:" -ForegroundColor Green
        Write-Host $command
        $output = Invoke-Expression $command

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Command executed successfully." -ForegroundColor Green
            # Extract and print the role assignment ID
            $roleAssignmentId = $output | ConvertFrom-Json | Select-Object -ExpandProperty id
            Write-Host "Role Assignment ID: $roleAssignmentId" -ForegroundColor Cyan
            return @{
                Success = $true
                AccountName = $CosmosDbAccountName
                JitApproved = $true
                RoleAssigned = $true
                RoleAssignmentId = $roleAssignmentId
            }
        }
        else {
            Write-Error "Command failed."
            return @{
                Success = $false
                Error = "Role assignment command failed"
                AccountName = $CosmosDbAccountName
                JitApproved = $true
                RoleAssigned = $false
            }
        }
    }
    catch {
        Write-Error "Unexpected error in Get-CosmosDBWriteAccess: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = "Unexpected error: $($_.Exception.Message)"
            AccountName = $CosmosDbAccountName
        }
    }
}

# Cmdlet: Revoke-CosmosDBAccess
function Revoke-CosmosDBAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$CosmosDbAccountName,
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        [Parameter()]
        [string]$PmeAlias,
        [Parameter()]
        [string]$PmeObjectId
    )
    if (-not (Test-AzCLI)) { return }
    if (-not (Set-AzSubscription -SubscriptionId $SubscriptionId)) { return }
    if ($PmeObjectId) {
        try {
            [guid]::Parse($PmeObjectId) | Out-Null
        }
        catch {
            Write-Error 'The provided PmeObjectId is not a valid GUID.'
            return
        }
    }
    # Use the provided PME Object ID or retrieve it using Get-PmeObjectId
    if (-not $PmeObjectId) {
        if (-not $PmeAlias) {
            Write-Error 'Either PmeAlias or PmeObjectId must be provided.'
            return
        }
        $PmeObjectId = Get-PmeObjectId -PmeAlias $PmeAlias
        if (-not $PmeObjectId) { return }
    }
    # Query the role assignment ID based on the PME Object ID
    $roleAssignmentCommand = @(
        'az cosmosdb sql role assignment list',
        '--account-name `"$CosmosDbAccountName`"',
        '--resource-group `"$ResourceGroupName`"',
        "--query '[?principalId=='$pmeObjectId'].id | [0]'",
        '-o tsv'
    ) -join ' '
    $roleAssignmentId = Invoke-Expression $roleAssignmentCommand
    if (-not $roleAssignmentId) {
        Write-Error 'Failed to retrieve the role assignment ID for PME Object ID: $pmeObjectId'
        return
    }
    $command = @(
        'az cosmosdb sql role assignment delete',
        '--account-name $CosmosDbAccountName',
        '--resource-group $ResourceGroupName',
        '--role-assignment-id $roleAssignmentId'
    ) -join ' '
    Write-Host 'Running the following command:' -ForegroundColor Green
    Write-Host $command
    Invoke-Expression $command
}

#endregion

#region Module Exports

# Export module functions
Export-ModuleMember -Function @(
    # Core Kusto query functions
    'Get-IntuneInventoryDetails',
    'Set-IntuneKustoConfiguration',

    # JIT access workflow functions
    'New-IntuneCosmosJitAccess',
    'Invoke-IntuneE2ECosmosAccess',

    # CosmosDB access functions
    'Get-CosmosDBReadAccess',
    'Get-CosmosDBWriteAccess',
    'Revoke-CosmosDBAccess',

    # Infrastructure support functions (commonly used)
    'Test-AzCLI',
    'Get-PmeObjectId',
    'Check-JITShellInstallation',
    'Init-JITShell',
    'Request-JITAccess'
)

#endregion
