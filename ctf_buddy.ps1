param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    $PythonExe = $VenvPython
} else {
    $PythonExe = "python"
}

Set-Location $RepoRoot
& $PythonExe (Join-Path $RepoRoot "main.py") @CliArgs
$ExitCode = $LASTEXITCODE

if ($null -ne $ExitCode) {
    exit $ExitCode
}
