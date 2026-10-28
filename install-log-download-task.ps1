param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$ProjectPath=$PSScriptRoot,
    [switch]$Preview
)
$ErrorActionPreference='Stop'
$configFile=(Resolve-Path -LiteralPath $ConfigPath).Path
$project=(Resolve-Path -LiteralPath $ProjectPath).Path
$config=Get-Content -LiteralPath $configFile -Raw -Encoding utf8 | ConvertFrom-Json
if (-not $config.enabled -or $config.transport -ne 'sftp') { throw 'SFTP_PROFILE_NOT_CONFIGURED' }
if ($config.daily_time -notmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$') { throw 'INVALID_DAILY_TIME' }
if ($configFile.Contains('"') -or $project.Contains('"')) { throw 'INVALID_TASK_PATH' }
$python=Join-Path $project '.venv\Scripts\python.exe'
$pythonHidden=Join-Path $project '.venv\Scripts\pythonw.exe'
$entry=Join-Path $project 'log_transfer.py'
if (-not (Test-Path -LiteralPath $pythonHidden)) { throw 'PYTHONW_REQUIRED' }
$validation=& $python $entry validate --config $configFile | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $validation.configured) { throw 'INVALID_SFTP_PROFILE' }
$name='FindingAssistant-LogDownload-'+$config.system_id
$action=New-ScheduledTaskAction -Execute $pythonHidden -Argument ('"'+$entry+'" pull --config "'+$configFile+'"') -WorkingDirectory $project
$trigger=New-ScheduledTaskTrigger -Daily -At $config.daily_time
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2)
$principal=New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
if ($Preview) { @{task_name=$name;daily_time=$config.daily_time;register=$false;requires_user_login=$true} | ConvertTo-Json;exit }
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'TASK_ALREADY_EXISTS_REVIEW_BEFORE_UPDATE' }
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description '只读增量下载找货助手日志，长期保留本地副本' | Select-Object TaskName,State
