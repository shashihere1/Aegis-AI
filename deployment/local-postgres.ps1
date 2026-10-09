param(
    [ValidateSet('Start', 'Status', 'Stop')][string]$Action = 'Start',
    [string]$BinaryDirectory = 'C:\Program Files\PostgreSQL\18\bin',
    [ValidateRange(1024, 65535)][int]$Port = 55432
)
$ErrorActionPreference = 'Stop'
$taskRepo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskRoot = Join-Path $taskRepo '.local\postgres'
$taskData = Join-Path $taskRoot 'data'
$taskPgCtl = Join-Path $BinaryDirectory 'pg_ctl.exe'
if (-not (Test-Path -LiteralPath $taskPgCtl)) { throw 'Approved PostgreSQL binaries were not found.' }

if ($Action -eq 'Status') {
    & $taskPgCtl status -D $taskData
    & (Join-Path $BinaryDirectory 'pg_isready.exe') -h 127.0.0.1 -p $Port -t 2
    exit $LASTEXITCODE
}
if ($Action -eq 'Stop') {
    if (-not (Test-Path -LiteralPath (Join-Path $taskData 'PG_VERSION'))) { throw 'No project-local cluster exists.' }
    & $taskPgCtl stop -D $taskData -m fast -w
    exit $LASTEXITCODE
}

New-Item -ItemType Directory -Path $taskRoot -Force | Out-Null
$taskLocal = Join-Path $taskRepo '.local'
$taskAccount = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls $taskLocal /inheritance:r /grant:r "${taskAccount}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict local state folder permissions.' }
$taskSecrets = Join-Path $taskRoot 'credentials.clixml'
function New-TaskPassword {
    $taskBytes = New-Object byte[] 32
    $taskRng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $taskRng.GetBytes($taskBytes) } finally { $taskRng.Dispose() }
    return ([BitConverter]::ToString($taskBytes)).Replace('-', '').ToLowerInvariant()
}
if (Test-Path -LiteralPath $taskSecrets) {
    $taskCredentials = Import-Clixml -LiteralPath $taskSecrets
} else {
    if (Test-Path -LiteralPath (Join-Path $taskData 'PG_VERSION')) {
        throw 'Cluster exists but its credentials are missing. Refusing to reset or overwrite it.'
    }
    $taskCredentials = @{
        Admin = New-Object PSCredential('postgres', (ConvertTo-SecureString (New-TaskPassword) -AsPlainText -Force))
        App = New-Object PSCredential('aegis_app', (ConvertTo-SecureString (New-TaskPassword) -AsPlainText -Force))
        Port = $Port
    }
    # Windows encrypts SecureString credentials for this user/machine. Never checked into Git.
    $taskCredentials | Export-Clixml -LiteralPath $taskSecrets
}
if (-not $taskCredentials.ContainsKey('InternalToken')) {
    $taskCredentials.InternalToken = ConvertTo-SecureString (New-TaskPassword) -AsPlainText -Force
    $taskCredentials | Export-Clixml -LiteralPath $taskSecrets
}
if ($taskCredentials.Port -ne $Port) {
    & $taskPgCtl status -D $taskData 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'Stop this project cluster before changing its port.' }
    $taskCredentials.Port = $Port
    $taskCredentials | Export-Clixml -LiteralPath $taskSecrets
}
if (-not (Test-Path -LiteralPath (Join-Path $taskData 'PG_VERSION'))) {
    $taskPwFile = Join-Path $taskRoot 'init-password.tmp'
    try {
        [IO.File]::WriteAllText($taskPwFile, $taskCredentials.Admin.GetNetworkCredential().Password)
        & (Join-Path $BinaryDirectory 'initdb.exe') -D $taskData -U postgres --encoding=UTF8 --locale=C --auth-host=scram-sha-256 --auth-local=scram-sha-256 --pwfile=$taskPwFile
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL initialization failed; existing files were preserved.' }
    } finally {
        if (Test-Path -LiteralPath $taskPwFile) { Remove-Item -LiteralPath $taskPwFile }
    }
}
& $taskPgCtl status -D $taskData 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    $taskStart = Start-Process -FilePath $taskPgCtl -ArgumentList @('-D', ('"' + $taskData + '"'), '-l', ('"' + (Join-Path $taskRoot 'server.log') + '"'), '-o', ('"-h 127.0.0.1 -p ' + $Port + '"'), '-w', 'start') -WindowStyle Hidden -PassThru
    # -Wait waits for the entire descendant tree, including the long-lived server.
    if (-not $taskStart.WaitForExit(60000)) { throw 'PostgreSQL startup helper timed out.' }
    $taskStart.Refresh()
    if ($taskStart.ExitCode -ne 0) { throw 'Could not start project-local PostgreSQL. Check .local/postgres/server.log; do not stop another database.' }
}

function Invoke-TaskSql([string]$Database, [string]$Sql) {
    $taskPreviousPassword = $env:PGPASSWORD
    try {
        $env:PGPASSWORD = $taskCredentials.Admin.GetNetworkCredential().Password
        # SQL goes through stdin; passwords are not exposed in process arguments or console output.
        $taskResult = $Sql | & (Join-Path $BinaryDirectory 'psql.exe') -X -w -h 127.0.0.1 -p $Port -U postgres -d $Database -v ON_ERROR_STOP=1 -At 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Database setup query failed. Credentials were not printed.' }
        return $taskResult
    } finally {
        $env:PGPASSWORD = $taskPreviousPassword
    }
}
$taskRoleExists = Invoke-TaskSql 'postgres' "SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app';"
if ($taskRoleExists -ne '1') {
    $taskAppPassword = $taskCredentials.App.GetNetworkCredential().Password
    Invoke-TaskSql 'postgres' ("CREATE ROLE aegis_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '" + $taskAppPassword + "';") | Out-Null
}
$taskDbExists = Invoke-TaskSql 'postgres' "SELECT 1 FROM pg_database WHERE datname = 'aegis';"
if ($taskDbExists -ne '1') { Invoke-TaskSql 'postgres' 'CREATE DATABASE aegis OWNER aegis_app;' | Out-Null }
$taskUrl = 'postgresql+asyncpg://aegis_app:' + $taskCredentials.App.GetNetworkCredential().Password + '@127.0.0.1:' + $Port + '/aegis'
$taskConfiguration = @{
    database_url = $taskUrl
    internal_token = (New-Object PSCredential('internal', $taskCredentials.InternalToken)).GetNetworkCredential().Password
    signing_key_path = (Join-Path $taskLocal 'keys\sts.pem')
    idp_key_path = (Join-Path $taskLocal 'keys\idp.pem')
    evidence_key_path = (Join-Path $taskLocal 'keys\evidence.pem')
    identity_state_dir = (Join-Path $taskLocal 'identities')
}
[IO.File]::WriteAllText((Join-Path $taskLocal 'connection.json'), ($taskConfiguration | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
Write-Output "Project-local PostgreSQL is ready on 127.0.0.1:$Port; database aegis."
Write-Output 'Aegis reads its protected, Git-ignored .local/connection.json. No Windows service was created.'
