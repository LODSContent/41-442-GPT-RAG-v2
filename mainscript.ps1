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

Write-Log "Environment variables loaded. Tenant=$tenantId, Sub=$subscriptionId, LabInstance=$labInstanceId, Location=$location"

$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$spCred = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

Write-Log "Connecting to Azure with Connect-AzAccount..."
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

Write-Log "Starting az CLI login..."
az login --service-principal --username $clientId --password $clientSecret --tenant $tenantId | Out-Null
Write-Log "Completed az CLI login."

$deployPath = "$HOME\gpt-rag-deploy"
Write-Log "Preparing deploy path: $deployPath (removing if exists)..."
Remove-Item -Recurse -Force $deployPath -ErrorAction SilentlyContinue | Out-Null

Write-Log "Cloning gpt-rag repo (branch 'agentic')..."
git clone -b agentic https://github.com/Azure/gpt-rag.git $deployPath | Out-Null
Set-Location $deployPath
Write-Log "Repository cloned and working directory set to $deployPath."

$yamlPath = Join-Path $deployPath "azure.yaml"
Write-Log "Writing clean azure.yaml template..."
$cleanYaml = @"
# yaml-language-server: \$schema=https://raw.githubusercontent.com/Azure/azure-dev/main/schemas/v1.0/azure.yaml.json
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

Write-Log "Running azd init for environment dev-$labInstanceId..."
azd init --environment dev-$labInstanceId --no-prompt | Out-Null
Write-Log "Initialized azd environment dev-$labInstanceId."

$infraScriptPath = Join-Path $deployPath "infra\scripts"
Write-Log "Removing preprovision and preDeploy scripts if present..."
Remove-Item -Force -ErrorAction SilentlyContinue "$infraScriptPath\preprovision.ps1"
Remove-Item -Force -ErrorAction SilentlyContinue "$infraScriptPath\preDeploy.ps1"
Write-Log "Removed pre-provision/deploy scripts"

$envFile = Join-Path $deployPath ".azure\dev-$labInstanceId\.env"
Write-Log "Checking .env file at $envFile for AZURE_NETWORK_ISOLATION..."
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile
    if ($envContent -notmatch "^AZURE_NETWORK_ISOLATION=") {
        Add-Content $envFile "`nAZURE_NETWORK_ISOLATION=true"
        Write-Log "Enabled AZURE_NETWORK_ISOLATION in .env file."
    } else {
        Write-Log "AZURE_NETWORK_ISOLATION already present in .env file."
    }
} else {
    Write-Log "[WARNING] .env file not found at $envFile"
}

$newKvName = "kv-$labInstanceId"
Write-Log "Updating Key Vault name references to $newKvName in infra templates..."
$kvFiles = Get-ChildItem -Recurse -Include *.bicep,*.json -ErrorAction SilentlyContinue
Write-Log "Found $($kvFiles.Count) infra template files to scan for Key Vault replacements."
foreach ($file in $kvFiles) {
    (Get-Content $file.FullName) -replace 'kv0-[a-z0-9]+', $newKvName | Set-Content $file.FullName
}
Write-Log "Key Vault name replacements complete."

$openaiBicep = Join-Path $deployPath "infra\core\ai\openai.bicep"
if (Test-Path $openaiBicep) {
    Write-Log "Commenting out OpenAI deployment in openai.bicep..."
    $lines = Get-Content $openaiBicep
    $commented = $lines | ForEach-Object { if ($_ -notmatch "^//") { "// $_" } else { $_ } }
    Set-Content -Path $openaiBicep -Value $commented
    Write-Log "Commented out OpenAI deployment in openai.bicep"
} else {
    Write-Log "[WARNING] openai.bicep not found at $openaiBicep"
}

Write-Log "Setting azd environment variables..."
azd env set AZURE_KEY_VAULT_NAME $newKvName | Out-Null
azd env set AZURE_SUBSCRIPTION_ID $subscriptionId | Out-Null
azd env set AZURE_LOCATION $location | Out-Null
az account set --subscription $subscriptionId | Out-Null
Write-Log "Configured azd env variables and active subscription."

azd env set AZURE_TAGS "LabInstance=$labInstanceId" | Out-Null
Write-Log "Set deployment tag: LabInstance=$labInstanceId"

# Path to the parameters file
$paramFilePath = Join-Path $deployPath "infra\main.parameters.json"
Write-Log "Loading parameters file at $paramFilePath..."

# Load and parse the JSON into a hashtable-like object
$paramJson = Get-Content -Raw -Path $paramFilePath | ConvertFrom-Json

# Create a hashtable for deploymentTags if needed
if (-not $paramJson.parameters.deploymentTags) {
    Write-Log "deploymentTags parameter missing; creating it."
    $paramJson.parameters.deploymentTags = @{ value = @{} }
}

# Overwrite or set the LabInstance tag in the value object
$paramJson.parameters.deploymentTags.value = @{ LabInstance = $labInstanceId }

# Write the updated JSON back to the file
$paramJson | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $paramFilePath
Write-Log "Successfully set deploymentTags: LabInstance = $labInstanceId"

Write-Log "Starting azd provision for dev-$labInstanceId..."
azd provision --environment dev-$labInstanceId 2>&1 | Tee-Object -FilePath $logFile -Append
Write-Log "azd provision complete"

# Assign Contributor role to service principal on the resource group
try {
    Write-Log "Attempting to assign Contributor role to SP on resource group (variable may be empty at this point)..."
    az role assignment create `
        --assignee $clientId `
        --assignee-principal-type ServicePrincipal `
        --role "Contributor" `
        --scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup" | Out-Null

    Write-Log "Assigned Contributor role to service principal on resource group: $resourceGroup"
} catch {
    Write-Log "[ERROR] Failed to assign Contributor role: $_"
}

Write-Log "Locating resource group matching pattern rg-dev-$labInstanceId..."
$resourceGroup = az group list --query "[?contains(name, 'rg-dev-$labInstanceId')].name" -o tsv
Write-Log "Resource group resolved to: $resourceGroup"

Write-Log "Checking for failed resources after provisioning..."

# List any failed resources in the resource group
$failedResources = az resource list --resource-group $resourceGroup `
    --query "[?provisioningState=='Failed']" -o json | ConvertFrom-Json

if ($failedResources.Count -gt 0) {
    Write-Log "[ERROR] Found failed resources:"
    foreach ($res in $failedResources) {
        Write-Log " - $($res.type): $($res.name)"
    }
} else {
    Write-Log "No failed resources found."
}

Write-Log "Searching for deployment named 'main' in resource group $resourceGroup..."
# Try to get the most recent deployment name (usually named 'main' if using azd)
$deploymentName = az deployment group list --resource-group $resourceGroup `
    --query "[?contains(name, 'main')].name" -o tsv

if ($deploymentName) {
    Write-Log "Found deployment: $deploymentName. Retrieving error details (if any)..."
    try {
        $errorDetails = az deployment group show --resource-group $resourceGroup `
            --name $deploymentName `
            --query "properties.error" -o json | ConvertFrom-Json

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

Write-Log "Setting AZURE_RESOURCE_GROUP environment value in azd env..."
azd env set AZURE_RESOURCE_GROUP $resourceGroup | Out-Null
Write-Log "Set resource group in azd env: $resourceGroup"

# === Retry OpenAI provisioning after azd provision ===
Write-Log "Checking OpenAI provisioning state after provisioning..."

$openAiAccountName = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.CognitiveServices/accounts" `
    --query "[?contains(name, 'oai0')].name" -o tsv

$openAiProvisioningState = ""
$maxAttempts = 10
$delaySeconds = 30

for ($i = 1; $i -le $maxAttempts; $i++) {
    if (-not $openAiAccountName) {
        Write-Log "[ERROR] Could not find OpenAI resource after provision."
        break
    }

    try {
        $openAiProvisioningState = az cognitiveservices account show `
            --name $openAiAccountName `
            --resource-group $resourceGroup `
            --query "provisioningState" -o tsv

        Write-Log "Post-provision OpenAI provisioning state: $openAiProvisioningState (Attempt $i)"

        if ($openAiProvisioningState -in @("Succeeded", "Failed", "Canceled", "Deleted")) {
            break
        }
    } catch {
        Write-Log "[WARNING] Failed to retrieve OpenAI provisioning state on attempt $i: $_"
    }

    Write-Log "Sleeping $delaySeconds seconds before next OpenAI provisioning check..."
    Start-Sleep -Seconds $delaySeconds
}

if ($openAiProvisioningState -ne "Succeeded") {
    Write-Log "[WARNING] OpenAI resource not in 'Succeeded' state — running fallback OpenAI provisioning script."

    $fallbackScriptPath = "$env:TEMP\openai.ps1"
    Write-Log "Downloading fallback OpenAI script to $fallbackScriptPath..."
    Invoke-WebRequest `
        -Uri "https://raw.githubusercontent.com/LODSContent/ProServ/refs/heads/main/41-442%20MS%20RAG%20GPT/openai.ps1" `
        -OutFile $fallbackScriptPath -UseBasicParsing

    Write-Log "Executing fallback OpenAI script..."
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

Write-Log "Searching for Bastion Key Vault (name starts with 'bastionkv')..."
# Find the Key Vault with a name starting with 'bastionkv'
$bastionKvName = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.KeyVault/vaults" `
    --query "[?starts_with(name, 'bastionkv')].name" -o tsv

if ($bastionKvName) {
    Write-Log "Found Bastion Key Vault: $bastionKvName. Assigning RBAC roles..."
    $bastionKvScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.KeyVault/vaults/$bastionKvName"
    $labUserUPN = "User1-$labInstanceId@lodsprodmca.onmicrosoft.com"

    try {
        Write-Log "Looking up lab user object ID for $labUserUPN..."
        $labUserObjectId = az ad user show --id $labUserUPN --query id -o tsv

        if ($labUserObjectId) {
            Write-Log "Assigning 'Key Vault Secrets User' to $labUserUPN on $bastionKvName..."
            az role assignment create `
                --assignee-object-id $labUserObjectId `
                --assignee-principal-type User `
                --role "Key Vault Secrets User" `
                --scope $bastionKvScope | Out-Null

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
Write-Log "Looking up lab user object ID for Search Service Contributor role: $labUserUPN"
$labUserObjectId = az ad user show --id $labUserUPN --query id -o tsv

Write-Log "Locating first search service in resource group $resourceGroup..."
$searchServiceName = az resource list `
    --resource-group $resourceGroup `
    --resource-type "Microsoft.Search/searchServices" `
    --query "[0].name" -o tsv

if ($labUserObjectId -and $searchServiceName) {
    $searchScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Search/searchServices/$searchServiceName"
    Write-Log "Assigning 'Search Service Contributor' to $labUserUPN on $searchServiceName..."

    az role assignment create `
        --assignee-object-id $labUserObjectId `
        --assignee-principal-type User `
        --role "Search Service Contributor" `
        --scope $searchScope | Out-Null

    Write-Log "Assigned 'Search Service Contributor' role to $labUserUPN on $searchServiceName"
} else {
    Write-Log "[ERROR] Could not retrieve lab user object ID or search service name for RBAC assignment."
}


# Retry OpenAI provisioning
Write-Log "Re-checking OpenAI provisioning state after fallback..."
$openAiAccountName = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.CognitiveServices/accounts" `
    --query "[?contains(name, 'oai0')].name" -o tsv

$provisioningState = ""
if ($openAiAccountName) {
    $provisioningState = az cognitiveservices account show `
        --name $openAiAccountName `
        --resource-group $resourceGroup `
        --query "provisioningState" -o tsv
    Write-Log "Final OpenAI provisioning state: $provisioningState"
} else {
    Write-Log "[WARNING] OpenAI account still not found when re-checking."
}

if (-not $openAiAccountName -or $provisioningState -ne "Succeeded") {
    Write-Log "[WARNING] OpenAI not in Succeeded state; invoking fallback OpenAI script again..."
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
    Write-Log "Retry fallback OpenAI provisioning executed (second pass)"
}

Write-Log "Locating storage account in $resourceGroup..."
$storageAccount = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.Storage/storageAccounts" `
    --query "sort_by([?type=='Microsoft.Storage/storageAccounts'], &length(name))[0].name" -o tsv
Write-Log "Using storage account: $storageAccount"

# Get the connection string from the storage account
Write-Log "Retrieving storage account connection string..."
$storageConnStr = az storage account show-connection-string `
    --name $storageAccount `
    --resource-group $resourceGroup `
    --query connectionString -o tsv

Write-Log "Connection string retrieved. Updating Function App app settings (if functions discovered)..."

# Set it on each Function App (dataIngest and orchestrator)
if ($ingestionFunc) {
    az functionapp config appsettings set `
        --name $ingestionFunc `
        --resource-group $resourceGroup `
        --settings AzureWebJobsStorage="$storageConnStr" | Out-Null
    Write-Log "Set AzureWebJobsStorage for $ingestionFunc"
} else {
    Write-Log "[WARNING] ingestionFunc variable is empty when trying to set AzureWebJobsStorage."
}

if ($orchestratorFunc) {
    az functionapp config appsettings set `
        --name $orchestratorFunc `
        --resource-group $resourceGroup `
        --settings AzureWebJobsStorage="$storageConnStr" | Out-Null
    Write-Log "Set AzureWebJobsStorage for $orchestratorFunc"
} else {
    Write-Log "[WARNING] orchestratorFunc variable is empty when trying to set AzureWebJobsStorage."
}

Write-Log "Looking up service principal object ID for $clientId..."
$objectId = az ad sp show --id $clientId --query id -o tsv

Write-Log "Assigning Storage Blob Data Contributor to service principal on storage account..."
az role assignment create `
    --assignee-object-id $objectId `
    --assignee-principal-type ServicePrincipal `
    --role "Storage Blob Data Contributor" `
    --scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Storage/storageAccounts/$storageAccount" | Out-Null

Write-Log "Assigned Storage Blob Data Contributor"

# === Assign RBAC to user on Storage Account ===
$labUserUPN = "User1-$labInstanceId@lodsprodmca.onmicrosoft.com"
Write-Log "Looking up lab user object ID for Storage Blob Data Contributor: $labUserUPN"
try {
    $labUserObjectId = az ad user show --id $labUserUPN --query id -o tsv

    if ($labUserObjectId) {
        Write-Log "Assigning 'Storage Blob Data Contributor' to $labUserUPN on $storageAccount..."
        az role assignment create `
            --assignee-object-id $labUserObjectId `
            --assignee-principal-type User `
            --role "Storage Blob Data Contributor" `
            --scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Storage/storageAccounts/$storageAccount" | Out-Null

        Write-Log "Assigned 'Storage Blob Data Contributor' role to $labUserUPN on $storageAccount"
    } else {
        Write-Log "[ERROR] Could not find lab user $labUserUPN"
    }
} catch {
    Write-Log "[ERROR] Failed to assign RBAC on Storage Account: $_"
}

Write-Log "Locating ingestion and orchestrator Function Apps..."
$ingestionFunc = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.Web/sites" `
    --query "[?contains(name, 'inges')].name" -o tsv
$orchestratorFunc = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.Web/sites" `
    --query "[?contains(name, 'orch')].name" -o tsv

Write-Log "ingestionFunc: $ingestionFunc; orchestratorFunc: $orchestratorFunc"

if ($ingestionFunc) {
    Write-Log "Configuring MULTIMODAL=true on $ingestionFunc and restarting..."
    az functionapp config appsettings set --name $ingestionFunc --resource-group $resourceGroup --settings MULTIMODAL=true | Out-Null
    az functionapp restart --name $ingestionFunc --resource-group $resourceGroup | Out-Null
}
if ($orchestratorFunc) {
    Write-Log "Configuring AUTOGEN_ORCHESTRATION_STRATEGY=multimodal_rag on $orchestratorFunc and restarting..."
    az functionapp config appsettings set --name $orchestratorFunc --resource-group $resourceGroup --settings AUTOGEN_ORCHESTRATION_STRATEGY=multimodal_rag | Out-Null
    az functionapp restart --name $orchestratorFunc --resource-group $resourceGroup | Out-Null
}
Write-Log "Function apps updated"

Write-Log "Locating frontend Web App (name contains 'webgpt')..."
$webAppName = az resource list --resource-group $resourceGroup `
    --resource-type "Microsoft.Web/sites" `
    --query "[?contains(name, 'webgpt')].name" -o tsv

if ($webAppName) {
    Write-Log "Found Web App: $webAppName. Retrieving URL..."
    $webAppUrl = az webapp show --name $webAppName --resource-group $resourceGroup --query "defaultHostName" -o tsv
    Write-Log "Deployment URL: https://$webAppUrl"
    Write-Host "Your GPT solution is live at: https://$webAppUrl"
} else {
    Write-Log "Web App not found."
}
Write-Log "Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
