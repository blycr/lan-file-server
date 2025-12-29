# Create LAN File Server Desktop Shortcut

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "     Create LAN File Server Desktop Shortcut" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Find the batch file (handle encoding issues)
$BatchFiles = Get-ChildItem -Path $ScriptDir -Filter "*.bat" | Where-Object { $_.Name -like "*LAN*" -or $_.Name -like "*文件*" -or $_.Name -like "*启动*" }

if ($BatchFiles.Count -eq 0) {
    Write-Host "[Error] No batch startup script found!" -ForegroundColor Red
    Write-Host "Please ensure the batch file exists in: $ScriptDir" -ForegroundColor Yellow
    Read-Host "Press any key to exit"
    exit 1
}

$ServerScript = $BatchFiles[0].FullName
Write-Host "[Info] Found startup script: $($BatchFiles[0].Name)" -ForegroundColor Green

# Get desktop path
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "LAN File Server.lnk"

try {
    # Create WScript.Shell object
    $WshShell = New-Object -comObject WScript.Shell
    
    # Create shortcut
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    
    # Set shortcut properties
    $Shortcut.TargetPath = $ServerScript
    $Shortcut.WorkingDirectory = $ScriptDir
    $Shortcut.Description = "LAN File Server - Local Network File Sharing Service"
    $Shortcut.Save()
    
    Write-Host "[Success] Desktop shortcut created!" -ForegroundColor Green
    Write-Host "Location: $ShortcutPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Shortcut Properties:" -ForegroundColor Yellow
    Write-Host "  Name: LAN File Server" -ForegroundColor White
    Write-Host "  Target: $(Split-Path $ServerScript -Leaf)" -ForegroundColor White
    Write-Host "  Working Directory: $ScriptDir" -ForegroundColor White
    Write-Host "  Description: 本地网络文件共享服务器" -ForegroundColor White
    
} catch {
    Write-Host "[Error] Failed to create shortcut!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Double-click the 'LAN File Server' shortcut on desktop to start the server" -ForegroundColor Cyan
Read-Host "Press any key to exit"