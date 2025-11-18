$logFile = "C:\labfiles\progress.log"

function Write-Log($msg) {
    $stamp = (Get-Date).ToString("yyyy-MM-dd HHmmss")
    Add-Content $logFile "[INFO] $stamp $msg"
}

Write-Log "=== Script started in GitHub version ==="

Write-Log "Loading environment variables..."
$tenantId       = $env:LAB_TENANT_ID
$subscriptionId = $env:LAB_SUBSCRIPTION_ID
$clientId       = $env:LAB_CLIENT_ID
$clientSecret   = $env:LAB_CLIENT_SECRET
$labInstanceId  = $env:LAB_INSTANCE_ID
$location       = $env:LAB_LOCATION
if (-not $location) { 
    Write-Log "LAB_LOCATION unset. Defaulting to eastus2."
    $location = "eastus2" 
}

Write-Log "Validating required environment variables..."
if (-not $tenantId -or -not $subscriptionId -or -not $clientId -or -not $clientSecret -or -not $labInstanceId) {
    Write-Log "[ERROR] One or more required environment variables are missing."
    return
}
Write-Log "Environment variables validated."

Write-Log "Preparing secure service principal credentials..."
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$spCred = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

Write-Log "Connecting to Azure using Connect-AzAccount..."
Connect-AzAccount -ServicePrincipal -Tenant $tenantId -Credential $spCred -Subscription $subscriptionId -SkipContextPopulation -ErrorAction Stop | Out-Null
Write-Log "Connected to Azure using Service Principal authentication."

Write-Log "Exporting AZURE_* environment variables for CLI tools..."
$env:AZURE_CLIENT_ID     = $clientId
$env:AZURE_CLIENT_SECRET = $clientSecret
$env:AZURE_TENANT_ID     = $tenantId
$env:AZD_NON_INTERACTIVE = "true"
$env:LAB_INSTANCE_ID     = $labInstanceId

Write-Log "Running: azd auth login..."
azd auth login --client-id $clientId --client-secret $clientSecret --tenant-id $tenantId | Out-Null
Write-Log "azd auth login complete."

Write-Log "Running: az login --service-principal..."
az login --service-principal --username $clientId --password $clientSecret --tenant $tenantId | Out-Null
Write-Log "az login complete."

$deployPath = "$HOME\gpt-rag-deploy"
Write-Log "Clearing old deployment folder at $deployPath..."
Remove-Item -Recurse -Force $deployPath -ErrorAction SilentlyContinue | Out-Null
Write-Log "Deploy folder cleared."

Write-Log "Cloning Azure/gpt-rag repository..."
git clone -b agentic https://github.com/Azure/gpt-rag.git $deployPath | Out-Null
Write-Log "Repository cloned successfully."

Write-Log "Switching to deploy directory..."
Set-Location $deployPath
Write-Log "Now in $deployPath."

Write-Log "Rewriting azure.yaml file..."
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
Write-Log "azure.yaml rewritten."

Write-Log "Preparing azd environment settings..."
$env:AZD_SKIP_UPDATE_CHECK = "true"
$env:AZD_DEFAULT_YES = "true"

Write-Log "Running: azd init..."
azd init --environment dev-$labInstanceId --no-prompt | Out-Null
Write-Log "azd init completed."

Write-Log "Removing preprovision and preDeploy scripts..."
$infraScriptPath = Join-Path $deployPath "infra\scripts"
Remove-Item -Force -ErrorAction SilentlyContinue "$infraScriptPath\preprovision.ps1"
Remove-Item -Force -ErrorAction SilentlyContinue "$infraScriptPath\preDeploy.ps1"
Write-Log "Pre-provision/deploy scripts removed."

Write-Log "Checking .env file for AZURE_NETWORK_ISOLATION..."
$envFile = Join-Path $deployPath ".azure\dev-$labInstanceId\.env"
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile
    if ($envContent -notmatch "^AZURE_NETWORK_ISOLATION=") {
        Add-Content $envFile "`nAZURE_NETWORK_ISOLATION=true"
        Write-Log "Added AZURE_NETWORK_ISOLATION=true"
    } else {
        Write-Log "AZURE_NETWORK_ISOLATION already set."
    }
} else {
    Write-Log "WARNING: .env file not found at $envFile"
}

Write-Log "Replacing Key Vault names in bicep/json files..."
$newKvName = "kv-$labInstanceId"
$kvFiles = Get-ChildItem -Recurse -Include *.bicep,*.json -ErrorAction SilentlyContinue
foreach ($file in $kvFiles) {
    (Get-Content $file.FullName) -replace 'kv0-[a-z0-9]+', $newKvName | Set-Content $file.FullName
}
Write-Log "Key Vault name replacements complete."

Write-Log "Commenting out OpenAI bicep file if present..."
$openaiBicep = Join-Path $deployPath "infra\core\ai\openai.bicep"
if (Test-Path $openaiBicep) {
    $lines = Get-Content $openaiBicep
    $commented = $lines | ForEach-Object { if ($_ -notmatch "^//") { "// $_" } else { $_ } }
    Set-Content -Path $openaiBicep -Value $commented
    Write-Log "Commented out OpenAI deployment."
} else {
    Write-Log "No openai.bicep file found."
}
