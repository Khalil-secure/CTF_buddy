param(
    [switch]$Local
)

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Runner = Join-Path $RepoRoot "ctf_buddy.ps1"

function Write-BuddyLine {
    param(
        [string]$Text = "",
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    Write-Host $Text -ForegroundColor $Color
}

function Write-BuddyRule {
    param(
        [ConsoleColor]$Color = [ConsoleColor]::DarkCyan
    )

    Write-Host ("=" * 72) -ForegroundColor $Color
}

function Write-BuddyPanel {
    param(
        [string]$Title,
        [string[]]$Lines,
        [ConsoleColor]$TitleColor = [ConsoleColor]::Cyan,
        [ConsoleColor]$TextColor = [ConsoleColor]::Gray
    )

    Write-BuddyRule
    Write-BuddyLine ("[ {0} ]" -f $Title.ToUpper()) $TitleColor
    foreach ($Line in $Lines) {
        Write-BuddyLine $Line $TextColor
    }
    Write-BuddyRule
}

function Write-BuddyStatus {
    param(
        [string]$Level,
        [string]$Text
    )

    $Color = switch ($Level.ToLower()) {
        "info" { [ConsoleColor]::Cyan }
        "hint" { [ConsoleColor]::DarkCyan }
        "warn" { [ConsoleColor]::Yellow }
        "hit" { [ConsoleColor]::Green }
        default { [ConsoleColor]::Gray }
    }

    Write-Host ("[{0}] " -f $Level.ToUpper()) -NoNewline -ForegroundColor $Color
    Write-Host $Text -ForegroundColor Gray
}

function Read-BuddyPrompt {
    param(
        [string]$Label,
        [string]$Hint = ""
    )

    Write-Host "buddy" -NoNewline -ForegroundColor Cyan
    Write-Host ">" -NoNewline -ForegroundColor DarkGray
    Write-Host (" {0}" -f $Label) -NoNewline -ForegroundColor White

    if ($Hint) {
        Write-Host (" [{0}]" -f $Hint) -NoNewline -ForegroundColor DarkGray
    }

    Write-Host ": " -NoNewline -ForegroundColor Gray
    return Read-Host
}

function Show-BuddyBanner {
    Clear-Host
    Write-BuddyLine "           .-.-." Cyan
    Write-BuddyLine "          |(o o)" Cyan
    Write-BuddyLine "           \\_/   ctf buddy" Cyan
    Write-BuddyLine "        .--'  '---. sidecar console" DarkCyan
    Write-BuddyRule DarkCyan
    Write-BuddyStatus "info" "Second terminal for quick challenge analysis."
    Write-BuddyStatus "hint" "Use it like a calm helper console: inspect, crack, decode, repeat."
    Write-BuddyLine ""
}

function Show-BuddyHelp {
    Write-BuddyPanel "Console" @(
        "Examples"
        "  network authentication challenge"
        "  kerberos pre-auth capture"
        "  dns zone transfer challenge"
        "  ftp auth challenge"
        ""
        "Flow"
        "  describe challenge -> add artifact -> choose mode -> run"
        ""
        "Exit"
        "  leave challenge empty to close"
    ) Cyan Gray
}

function Build-Args {
    param(
        [string]$Description,
        [string]$FilePath,
        [string]$Wordlist,
        [string]$Domain,
        [string]$Server,
        [string]$Port,
        [bool]$UseLocal
    )

    $Args = @($Description)

    if (-not [string]::IsNullOrWhiteSpace($FilePath)) {
        $Args += "--file"
        $Args += $FilePath
    }

    if (-not [string]::IsNullOrWhiteSpace($Wordlist)) {
        $Args += "--wordlist"
        $Args += $Wordlist
    }

    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $Args += "--domain"
        $Args += $Domain
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $Args += "--server"
        $Args += $Server
    }

    if (-not [string]::IsNullOrWhiteSpace($Port)) {
        $Args += "--port"
        $Args += $Port
    }

    if ($UseLocal) {
        $Args += "--local"
    }

    return $Args
}

Set-Location $RepoRoot
Show-BuddyBanner
Show-BuddyHelp

while ($true) {
    Write-BuddyLine ""
    $Description = Read-BuddyPrompt "challenge" "what are we solving"
    if ([string]::IsNullOrWhiteSpace($Description)) {
        break
    }

    Write-BuddyStatus "info" "Collecting inputs."
    $FilePath = Read-BuddyPrompt "artifact" "pcap or challenge file"
    $Wordlist = Read-BuddyPrompt "wordlist" "optional custom path"
    $Domain = Read-BuddyPrompt "domain" "for dns challenges"
    $Server = Read-BuddyPrompt "server" "dns host"
    $Port = Read-BuddyPrompt "port" "dns port"

    $UseLocal = $Local.IsPresent
    if (-not $UseLocal) {
        $LocalPrompt = Read-BuddyPrompt "mode" "local or agent"
        if ($LocalPrompt -match '^(local|l|y|yes)$') {
            $UseLocal = $true
        }
    }

    $Args = Build-Args -Description $Description -FilePath $FilePath -Wordlist $Wordlist -Domain $Domain -Server $Server -Port $Port -UseLocal $UseLocal

    $ArtifactSummary = if ([string]::IsNullOrWhiteSpace($FilePath)) { "none" } else { $FilePath }
    $ModeSummary = if ($UseLocal) { "local" } else { "agent" }

    Write-BuddyPanel "Status" @(
        ("target    : {0}" -f $Description)
        ("artifact  : {0}" -f $ArtifactSummary)
        ("mode      : {0}" -f $ModeSummary)
        ("next step : run analysis")
    ) Green Gray

    & $Runner @Args

    Write-BuddyLine ""
    $Again = Read-BuddyPrompt "next" "enter to continue, exit to close"
    if ($Again -match '^(exit|quit|q)$') {
        break
    }
}

Write-BuddyRule DarkGray
Write-BuddyStatus "info" "CTF Buddy terminal closed."
Write-BuddyRule DarkGray
