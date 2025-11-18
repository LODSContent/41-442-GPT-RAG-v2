$logFile = "C:\labfiles\progress.log"

function Write-Log($msg) {
    $stamp = (Get-Date).ToString("yyyy-MM-dd HHmmss")
    Add-Content $logFile "[INFO] $stamp $msg"
}

Write-Log "Script started in GitHub version."

$tenantId       = $env:LAB_TENANT_ID
$subscriptionId = $env:LAB_SUBSCRIPTION_ID
$clientId       = $env:LAB_CLIENT_ID
$clientSecret   = $env:LAB_CLIENT_SECRET
$labInstanceId  = $env:LAB_INSTANCE_ID
$location       = $env:LAB_LOCATION
if (-not $location) { $location = "eastus2" }

if (-not $tenantId -or -not $subscriptionId -or -not $clientId -or -not $clientSecret -or -not $labInstanceId) {
    Write-Log "[ERROR] One or more required environment variables are missing."
    return
}

$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$spCred = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

Connect-AzAccount -ServicePrincipal -Tenant $tenantId -Credential $spCred -Subscription $subscriptionId -SkipContextPopulation -ErrorAction Stop | Out-Null

Write-Log "Connected to Azure using Service Principal authentication."

$env:AZURE_CLIENT_ID     = $clientId
$env:AZURE_CLIENT_SECRET = $clientSecret
$env:AZURE_TENANT_ID     = $tenantId
$env:AZD_NON_INTERACTIVE = "true"
$env:LAB_INSTANCE_ID     = $labInstanceId

Write-Log "Starting azd auth login..."
azd auth login --client-id $clientId --client-secret $clientSecret --tenant-id $tenantId | Out-Null
Write-Log "Completed azd auth login."

# NOTE: Removed az login --service-principal to avoid hanging on large tenants

$deployPath = "$HOME\gpt-rag-deploy"
Write-Log "Cleaning deploy path: $deployPath"
Remove-Item -Recurse -Force $deployPath -ErrorAction SilentlyContinue | Out-Null
Write-Log "Deploy path cleaned (if existed)."

Write-Log "Starting git clone to $deployPath..."
git clone -b agentic https://github.com/Azure/gpt-rag.git $deployPath | Out-Null
Write-Log "Git clone completed."

Set-Location $deployPath
Write-Log "Set-Location to $deployPath"

$yamlPath = Join-Path $deployPath "azure.yaml"
$cleanYaml = @"
# yaml-language-server: $schema=https://raw.githubusercontent.com/Azure/azure-dev/main/schemas/v1.0/azure.yaml.json
name: azure-gpt-rag
metadata:
  template: azure-gpt-rag
services:
  dataIngest:
    project: ./.azure/gpt-rag-ingestion
    language: python
    host: function
  orchestrator:
    project: ./.azure/gpt-rag-orchestrator
    language: python
    host: function
  frontend:
    project: ./.azure/gpt-rag-frontend
    language: python
    host: appservice
"@
Set-Content -Path $yamlPath -Value $cleanYaml -Encoding UTF8
Write-Log "Cleaned azure.yaml"

$env:AZD_SKIP_UPDATE_CHECK = "true"
$env:AZD_DEFAULT_YES = "true"

Write-Log "Starting azd init for dev-$labInstanceId..."
azd init --environment dev-$labInstanceId --no-prompt | Out-Null
Write-Log "Initialized azd environment"

$infraScriptPath = Join-Path $deployPath "infra\scripts"
Remove-Item -Force -ErrorAction SilentlyContinue "$infraScriptPath\preprovision.ps1"
Remove-Item -Force -ErrorAction SilentlyContinue "$infraScriptPath\preDeploy.ps1"
Write-Log "Removed pre-provision/deploy scripts"

$envFile = Join-Path $deployPath ".azure\dev-$labInstanceId\.env"
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile
    if ($envContent -notmatch "^AZURE_NETWORK_ISOLATION=") {
        Add-Content $envFile "`nAZURE_NETWORK_ISOLATION=true"
        Write-Log "Enabled AZURE_NETWORK_ISOLATION"
    }
}
$newKvName = "kv-$labInstanceId"
$kvFiles = Get-ChildItem -Recurse -Include *.bicep,*.json -ErrorAction SilentlyContinue
foreach ($file in $kvFiles) {
    (Get-Content $file.FullName) -replace 'kv0-[a-z0-9]+', $newKvName | Set-Content $file.FullName
}

$openaiBicep = Join-Path $deployPath "infra\core\ai\openai.bicep"
if (Test-Path $openaiBicep) {
    $lines = Get-Content $openaiBicep
    $commented = $lines | ForEach-Object { if ($_ -notmatch "^//") { "// $_" } else { $_ } }
    Set-Content -Path $openaiBicep -Value $commented
    Write-Log "Commented out OpenAI deployment in openai.bicep"
}

azd env set AZURE_KEY_VAULT_NAME $newKvName | Out-Null
azd env set AZURE_SUBSCRIPTION_ID $subscriptionId | Out-Null
azd env set AZURE_LOCATION $location | Out-Null
# az account set removed – Connect-AzAccount already set subscription context
Write-Log "Configured azd env variables"

azd env set AZURE_TAGS "LabInstance=$labInstanceId" | Out-Null
Write-Log "Set deployment tag: LabInstance=$labInstanceId"

# Path to the parameters file
$paramFilePath = Join-Path $deployPath "infra\main.parameters.json"

# Load and parse the JSON into a hashtable-like object
$paramJson = Get-Content -Raw -Path $paramFilePath | ConvertFrom-Json

# Create a hashtable for deploymentTags if needed
if (-not $paramJson.parameters.deploymentTags) {
    $paramJson.parameters.deploymentTags = @{ value = @{} }
}

# Overwrite or set the LabInstance tag in the value object
$paramJson.parameters.deploymentTags.value = @{ LabInstance = $labInstanceId }

# Write the updated JSON back to the file
$paramJson | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $paramFilePath

Write-Log "Successfully set deploymentTags: LabInstance = $labInstanceId"

Write-Log "Starting azd provision"
azd provision --environment dev-$labInstanceId 2>&1 | Tee-Object -FilePath $logFile -Append
Write-Log "azd provision complete"

# Assign Contributor role to service principal on the resource group
try {
    New-AzRoleAssignment `
        -ApplicationId $clientId `
        -RoleDefinitionName "Contributor" `
        -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup" | Out-Null

    Write-Log "Assigned Contributor role to service principal on resource group: $resourceGroup"
} catch {
    Write-Log "[ERROR] Failed to assign Contributor role: $_"
}

# Resolve resource group (matching original az query logic)
$resourceGroup = (Get-AzResourceGroup |
    Where-Object { $_.ResourceGroupName -like "*rg-dev-$labInstanceId*" } |
    Select-Object -First 1).ResourceGroupName

Write-Log "Checking for failed resources after provisioning..."

# List any failed resources in the resource group
$failedResources = Get-AzResource -ResourceGroupName $resourceGroup | Where-Object {
    $_.Properties.provisioningState -eq 'Failed'
}

if ($failedResources.Count -gt 0) {
    Write-Log "[ERROR] Found failed resources:"
    foreach ($res in $failedResources) {
        Write-Log " - $($res.type): $($res.name)"
    }
} else {
    Write-Log "No failed resources found."
}

# Try to get the most recent deployment name (usually named 'main' if using azd)
$deploymentName = (Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroup |
    Where-Object { $_.DeploymentName -like "*main*" } |
    Select-Object -First 1).DeploymentName

if ($deploymentName) {
    try {
        $deployment   = Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -Name $deploymentName
        $errorDetails = $deployment.Properties.Error

        if ($errorDetails -ne $null) {
            Write-Log "[ERROR] Deployment error: $($errorDetails.message)"
            if ($errorDetails.details) {
                foreach ($detail in $errorDetails.details) {
                    Write-Log "  - $($detail.message)"
                }
            }
        } else {
            Write-Log "No top-level error message in deployment output."
        }
    } catch {
        Write-Log "[ERROR] Failed to retrieve deployment error details: $_"
    }
} else {
    Write-Log "No deployment named 'main' found in resource group."
}

azd env set AZURE_RESOURCE_GROUP $resourceGroup | Out-Null
Write-Log "Set resource group: $resourceGroup"

# === Retry OpenAI provisioning after azd provision ===
Write-Log "Checking OpenAI provisioning state after provisioning..."

$openAiAccountName = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceType "Microsoft.CognitiveServices/accounts" |
    Where-Object { $_.Name -like "*oai0*" } |
    Select-Object -First 1).Name

$openAiProvisioningState = ""
$maxAttempts = 10
$delaySeconds = 30

for ($i = 1; $i -le $maxAttempts; $i++) {
    if (-not $openAiAccountName) {
        Write-Log "[ERROR] Could not find OpenAI resource after provision."
        break
    }

    try {
        $openAiProvisioningState = (Get-AzCognitiveServicesAccount `
            -Name $openAiAccountName `
            -ResourceGroupName $resourceGroup).ProvisioningState

        Write-Log "Post-provision OpenAI provisioning state: $openAiProvisioningState (Attempt $i)"

        if ($openAiProvisioningState -in @("Succeeded", "Failed", "Canceled", "Deleted")) {
            break
        }
    } catch {
        Write-Log "[WARNING] Failed to retrieve OpenAI provisioning state: $_"
    }

    Start-Sleep -Seconds $delaySeconds
}

if ($openAiProvisioningState -ne "Succeeded") {
    Write-Log "[WARNING] OpenAI resource not in 'Succeeded' state — running fallback OpenAI provisioning script."

    $fallbackScriptPath = "$env:TEMP\openai.ps1"
    Invoke-WebRequest `
        -Uri "https://raw.githubusercontent.com/LODSContent/ProServ/refs/heads/main/41-442%20MS%20RAG%20GPT/openai.ps1" `
        -OutFile $fallbackScriptPath -UseBasicParsing

    & $fallbackScriptPath `
        -subscriptionId $subscriptionId `
        -resourceGroup $resourceGroup `
        -location $location `
        -labInstanceId $labInstanceId `
        -clientId $clientId `
        -clientSecret $clientSecret `
        -tenantId $tenantId `
        -logFile $logFile

    Write-Log "Retry fallback OpenAI provisioning executed"
}

# Find the Key Vault with a name starting with 'bastionkv'
$bastionKvName = (Get-AzKeyVault -ResourceGroupName $resourceGroup |
    Where-Object { $_.VaultName -like "bastionkv*" } |
    Select-Object -First 1).VaultName

if ($bastionKvName) {
    $bastionKvScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.KeyVault/vaults/$bastionKvName"
    $labUserUPN = "User1-$labInstanceId@lodsprodmca.onmicrosoft.com"

    try {
        $labUserObjectId = (Get-AzADUser -UserPrincipalName $labUserUPN).Id

        if ($labUserObjectId) {
            New-AzRoleAssignment `
                -ObjectId $labUserObjectId `
                -RoleDefinitionName "Key Vault Secrets User" `
                -Scope $bastionKvScope | Out-Null

            Write-Log "Assigned 'Key Vault Secrets User' role to $labUserUPN on $bastionKvName"
        } else {
            Write-Log "[ERROR] Could not find lab user $labUserUPN"
        }
    } catch {
        Write-Log "[ERROR] Failed to assign RBAC on Bastion Key Vault: $_"
    }
} else {
    Write-Log "[ERROR] Could not find Bastion Key Vault in resource group $resourceGroup"
}

# === Assign Search Service Contributor role to lab user ===
$labUserUPN = "User1-$labInstanceId@lodsprodmca.onmicrosoft.com"
$labUserObjectId = (Get-AzADUser -UserPrincipalName $labUserUPN).Id

$searchServiceName = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceType "Microsoft.Search/searchServices" |
    Select-Object -First 1).Name

if ($labUserObjectId -and $searchServiceName) {
    $searchScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Search/searchServices/$searchServiceName"

    New-AzRoleAssignment `
        -ObjectId $labUserObjectId `
        -RoleDefinitionName "Search Service Contributor" `
        -Scope $searchScope | Out-Null

    Write-Log "Assigned 'Search Service Contributor' role to $labUserUPN on $searchServiceName"
} else {
    Write-Log "[ERROR] Could not retrieve lab user object ID or search service name for RBAC assignment."
}

# Retry OpenAI provisioning
$openAiAccountName = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceType "Microsoft.CognitiveServices/accounts" |
    Where-Object { $_.Name -like "*oai0*" } |
    Select-Object -First 1).Name

$provisioningState = ""
if ($openAiAccountName) {
    $provisioningState = (Get-AzCognitiveServicesAccount `
        -Name $openAiAccountName `
        -ResourceGroupName $resourceGroup).ProvisioningState
}

if (-not $openAiAccountName -or $provisioningState -ne "Succeeded") {
    $fallbackScriptPath = "$env:TEMP\openai.ps1"
    Invoke-WebRequest `
        -Uri "https://raw.githubusercontent.com/LODSContent/ProServ/refs/heads/main/41-442%20MS%20RAG%20GPT/openai.ps1" `
        -OutFile $fallbackScriptPath -UseBasicParsing

    & $fallbackScriptPath `
        -subscriptionId $subscriptionId `
        -resourceGroup $resourceGroup `
        -location $location `
        -labInstanceId $labInstanceId `
        -clientId $clientId `
        -clientSecret $clientSecret `
        -tenantId $tenantId `
        -logFile $logFile
    Write-Log "Retry fallback OpenAI provisioning executed"
}

# Storage account selection (shortest name, same as original sort_by &length(name))
$storageAccount = (Get-AzStorageAccount -ResourceGroupName $resourceGroup |
    Sort-Object { $_.StorageAccountName.Length } |
    Select-Object -First 1).StorageAccountName

# Get the connection string from the storage account
$storageAccountObj  = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAccount
$storageAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $resourceGroup -Name $storageAccount
$primaryKey = ($storageAccountKeys | Select-Object -First 1).Value
$storageConnStr = "DefaultEndpointsProtocol=https;AccountName=$($storageAccountObj.StorageAccountName);AccountKey=$primaryKey;EndpointSuffix=core.windows.net"

# Set it on each Function App (dataIngest and orchestrator)
if ($ingestionFunc) {
    $appSettings = @{ "AzureWebJobsStorage" = $storageConnStr }
    Set-AzWebApp -Name $ingestionFunc -ResourceGroupName $resourceGroup -AppSettings $appSettings | Out-Null
    Write-Log "Set AzureWebJobsStorage for $ingestionFunc"
}

if ($orchestratorFunc) {
    $appSettings = @{ "AzureWebJobsStorage" = $storageConnStr }
    Set-AzWebApp -Name $orchestratorFunc -ResourceGroupName $resourceGroup -AppSettings $appSettings | Out-Null
    Write-Log "Set AzureWebJobsStorage for $orchestratorFunc"
}

$objectId = (Get-AzADServicePrincipal -ApplicationId $clientId).Id

New-AzRoleAssignment `
    -ObjectId $objectId `
    -RoleDefinitionName "Storage Blob Data Contributor" `
    -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Storage/storageAccounts/$storageAccount" | Out-Null

Write-Log "Assigned Storage Blob Data Contributor"

# === Assign RBAC to user on Storage Account ===
$labUserUPN = "User1-$labInstanceId@lodsprodmca.onmicrosoft.com"
try {
    $labUserObjectId = (Get-AzADUser -UserPrincipalName $labUserUPN).Id

    if ($labUserObjectId) {
        New-AzRoleAssignment `
            -ObjectId $labUserObjectId `
            -RoleDefinitionName "Storage Blob Data Contributor" `
            -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Storage/storageAccounts/$storageAccount" | Out-Null

        Write-Log "Assigned 'Storage Blob Data Contributor' role to $labUserUPN on $storageAccount"
    } else {
        Write-Log "[ERROR] Could not find lab user $labUserUPN"
    }
} catch {
    Write-Log "[ERROR] Failed to assign RBAC on Storage Account: $_"
}

$ingestionFunc = (Get-AzWebApp -ResourceGroupName $resourceGroup |
    Where-Object { $_.Name -like "*inges*" } |
    Select-Object -First 1).Name
$orchestratorFunc = (Get-AzWebApp -ResourceGroupName $resourceGroup |
    Where-Object { $_.Name -like "*orch*" } |
    Select-Object -First 1).Name

if ($ingestionFunc) {
    $settings = @{ "MULTIMODAL" = "true" }
    Set-AzWebApp -Name $ingestionFunc -ResourceGroupName $resourceGroup -AppSettings $settings | Out-Null
    Restart-AzWebApp -Name $ingestionFunc -ResourceGroupName $resourceGroup | Out-Null
}
if ($orchestratorFunc) {
    $settings = @{ "AUTOGEN_ORCHESTRATION_STRATEGY" = "multimodal_rag" }
    Set-AzWebApp -Name $orchestratorFunc -ResourceGroupName $resourceGroup -AppSettings $settings | Out-Null
    Restart-AzWebApp -Name $orchestratorFunc -ResourceGroupName $resourceGroup | Out-Null
}
Write-Log "Function apps updated"

$webAppName = (Get-AzWebApp -ResourceGroupName $resourceGroup |
    Where-Object { $_.Name -like "*webgpt*" } |
    Select-Object -First 1).Name

if ($webAppName) {
    $webAppUrl = (Get-AzWebApp -Name $webAppName -ResourceGroupName $resourceGroup).DefaultHostName
    Write-Log "Deployment URL: https://$webAppUrl"
    Write-Host "Your GPT solution is live at: https://$webAppUrl"
} else {
    Write-Log "Web App not found."
}
Write-Log "Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
