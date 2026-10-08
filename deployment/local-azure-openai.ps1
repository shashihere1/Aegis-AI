<# Load Azure settings into this PowerShell process. No file writes, server restart or network calls. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [Parameter(Mandatory = $true)][string]$Deployment,
    [Parameter(Mandatory = $true)][string]$ApiVersion
)

$ErrorActionPreference = 'Stop'
$taskAzureUri = $null
if (-not [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$taskAzureUri) -or
    $taskAzureUri.Scheme -ne 'https' -or $taskAzureUri.Port -ne 443 -or
    $taskAzureUri.Host -notmatch '^[a-z0-9][a-z0-9-]*\.(openai|services\.ai)\.azure\.com$' -or
    $taskAzureUri.UserInfo -or $taskAzureUri.Query -or $taskAzureUri.Fragment -or
    $taskAzureUri.AbsolutePath -ne '/') {
    throw 'Use the HTTPS Azure resource base endpoint only, without a deployment path or query.'
}
if ($Deployment -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or
    $ApiVersion -notmatch '^\d{4}-\d{2}-\d{2}(-preview)?$') {
    throw 'Supply a valid deployment name and a dated Azure API version.'
}

$taskAzureKey = Read-Host 'Azure API key (hidden; stays in this PowerShell process)' -AsSecureString
try {
    $taskKeyCredential = [System.Net.NetworkCredential]::new('', $taskAzureKey)
    if ([string]::IsNullOrWhiteSpace($taskKeyCredential.Password)) {
        throw 'An API key is required. No settings were changed.'
    }
    $env:AEGIS_AZURE_OPENAI_ENDPOINT = $Endpoint.TrimEnd('/')
    $env:AEGIS_AZURE_OPENAI_DEPLOYMENT = $Deployment
    $env:AEGIS_AZURE_OPENAI_API_VERSION = $ApiVersion
    $env:AEGIS_AZURE_OPENAI_API_KEY = $taskKeyCredential.Password
} finally {
    $taskAzureKey.Dispose()
    $taskKeyCredential = $null
}

Write-Output 'Azure settings loaded for programs launched from this terminal. No Azure call was made.'
Write-Output 'The key is a process environment variable, not an encrypted vault. Do not print or share it.'
Write-Output 'The running console was not changed. Launch the updated app from this terminal when ready.'
