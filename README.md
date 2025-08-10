# Kusto PowerShell Query Solution - Complete Documentation

## Overview
This solution provides a comprehensive PowerShell script for querying Azure Data Explorer (Kusto) databases, specifically designed for Intune data analysis and CosmosDB JIT access command generation.

## Files in Solution

### 1. `Inventory-Kusto-Clean.ps1` (Main Script)
The primary script that connects to Kusto, executes queries, and optionally generates JIT access commands.

**Key Features:**
- Multiple authentication methods (UserPrompt, AzureCLI, ApplicationCertificate)
- Flexible DLL loading with auto-detection
- Configurable query parameters (MicroServiceName, ScaleUnit)
- JIT access command generation for CosmosDB resources
- Isolated execution via PowerShell jobs
- Comprehensive error handling and troubleshooting guidance

### 2. `Test-KustoLoading.ps1` (Test Wrapper)
A testing script that helps validate the main script functionality and assembly loading.

**Features:**
- Assembly loading verification
- JIT command generation testing
- Isolated test execution
- Configurable test parameters

### 3. `Usage-Examples.ps1` (Documentation)
Comprehensive usage examples and scenarios for both scripts.

### 4. `Inventory-Kusto-REST.ps1` (Alternative)
REST API-based alternative for environments where DLL loading is problematic.

## Core Functionality

### Authentication Methods
1. **UserPrompt (Default):** Interactive Azure AD login
2. **AzureCLI:** Uses existing Azure CLI session
3. **ApplicationCertificate:** Service principal with certificate

### Query Configuration
- **Cluster:** `https://intuneinternal.kusto.windows.net`
- **Database:** `IntuneInternal`
- **Query:** Filters `InventoryDetails` by MicroServiceName and ScaleUnit
- **Default Filters:** RACerts service, AMSUA0101 scale unit

### JIT Access Command Generation
The script can automatically generate `get-cosmosdbreadaccess` commands using data from Kusto query results:

```powershell
get-cosmosdbreadaccess `
    -SubscriptionId <from-query> `
    -CosmosDbAccountName <extracted-from-data> `
    -ResourceGroupName <from-query> `
    -Justification "Custom justification" `
    -Env "Product" `
    -Src Other `
    -Wid 1234 `
    -PmeAlias username
```

## Usage Examples

### Basic Query
```powershell
.\Inventory-Kusto-Clean.ps1
```

### Query with JIT Command Generation
```powershell
.\Inventory-Kusto-Clean.ps1 -GenerateJitCommands -Justification "Certificate investigation"
```

### Custom Parameters
```powershell
.\Inventory-Kusto-Clean.ps1 `
    -MicroServiceName "DeviceRegistration" `
    -ScaleUnit "EUSNA0101" `
    -GenerateJitCommands `
    -Justification "Device registration troubleshooting"
```

### Azure CLI Authentication
```powershell
.\Inventory-Kusto-Clean.ps1 -AuthMethod AzureCLI
```

### Isolated Execution
```powershell
.\Inventory-Kusto-Clean.ps1 -RunInJob
```

## Troubleshooting

### Common Issues

1. **Assembly Loading Conflicts**
   - Solution: Use `-RunInJob` parameter
   - Alternative: Restart PowerShell session

2. **Missing Dependencies**
   - Solution: Download complete Kusto Tools NuGet package
   - Alternative: Use REST API version

3. **Authentication Failures**
   - Check tenant permissions
   - Verify Azure CLI login status
   - Validate certificate configuration

4. **DLL Not Found**
   - Use `-KustoDllPath` parameter
   - Check auto-detection search paths
   - Download Kusto Tools manually

### Error Recovery
The script includes comprehensive error handling with specific guidance for:
- Authentication failures (401 errors)
- Assembly loading issues
- Missing dependencies
- Connection timeouts
- Invalid query parameters

## Security Considerations

1. **Authentication:** Supports secure methods including certificate-based auth
2. **Permissions:** Requires appropriate Kusto cluster access
3. **Isolation:** Job execution prevents session pollution
4. **Logging:** Minimal sensitive data exposure in logs

## Extensibility

The script is designed to be easily extended:

1. **Additional Authentication Methods:** Add new cases to the auth switch statement
2. **Custom Queries:** Modify the `$KustoQuery` variable
3. **Output Formats:** Add formatting options after query execution
4. **Additional JIT Commands:** Extend the `New-JitAccessCommand` function

## Best Practices

1. **Use Azure CLI authentication for automation**
2. **Enable JIT command generation for operational tasks**
3. **Use `-RunInJob` for testing or when encountering conflicts**
4. **Specify custom DLL paths in CI/CD environments**
5. **Include meaningful justifications for audit trails**

## Performance Considerations

- Query timeout: 60 seconds (configurable)
- Client request ID: Auto-generated for tracking
- Memory usage: Minimal with streaming results
- Assembly loading: One-time cost per session

## Deployment

### Prerequisites
- PowerShell 5.1+ or PowerShell 7+
- Kusto.Data.dll and dependencies
- Azure authentication (CLI, certificate, or interactive)
- Network access to Kusto cluster

### Installation
1. Copy script files to target directory
2. Download Kusto Tools NuGet package (optional)
3. Configure authentication method
4. Test with `Test-KustoLoading.ps1`

## Support

For issues:
1. Check error messages and built-in troubleshooting guidance
2. Try alternative authentication methods
3. Use REST API version as fallback
4. Review dependency requirements
5. Test in isolated job execution mode

This solution provides a robust, flexible, and user-friendly approach to Kusto data analysis with integrated JIT access capabilities.
