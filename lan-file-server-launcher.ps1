# LAN File Server Unified Launcher
# Integrated PowerShell and CMD script functionality
# UTF-8 Encoded for International Support

param(
    [switch]$CreateShortcut,
    [switch]$Initialize,
    [switch]$Help
)

# Set console encoding to UTF-8 for proper international character display
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
    # Some CMD environments may not support this
}

# Set window title
try {
    $Host.UI.RawUI.WindowTitle = "LAN File Server Launcher"
} catch {
    # Some environments may not support this
}

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OriginalDir = Get-Location

Set-Location $ScriptDir

# Color output function (supports CMD environment)
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    # Try colored output
    try {
        if ($Host.UI.SupportsVirtualTerminal -or $Host.Name -eq "ConsoleHost") {
            $colorMap = @{
                "Red" = "Red"
                "Green" = "Green"
                "Yellow" = "Yellow"
                "Cyan" = "Cyan"
                "White" = "White"
                "Gray" = "Gray"
            }
            if ($colorMap.ContainsKey($Color)) {
                Write-Host $Message -ForegroundColor $colorMap[$Color]
                return
            }
        }
    } catch {
        # Fall back to basic output
    }
    
    # Basic output
    Write-Host $Message
}

# Show help information
function Show-Help {
    Write-Host ""
    Write-Host "LAN 文件服务器启动器帮助" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "用法:" -ForegroundColor White
    Write-Host "  .\lan-file-server-launcher.ps1              # 启动服务器" -ForegroundColor Gray
    # Write-Host "  .\lan-file-server-launcher.ps1 -Initialize   # 初始化服务器配置" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -CreateShortcut # 创建桌面快捷方式" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -Help        # 显示此帮助" -ForegroundColor Gray
    Write-Host ""
    Write-Host "主菜单选项:" -ForegroundColor White
    Write-Host "  1. 启动服务器" -ForegroundColor Green
    # Write-Host "  2. 初始化服务器配置" -ForegroundColor Yellow
    Write-Host "  3. 创建桌面快捷方式" -ForegroundColor Yellow
    Write-Host "  4. 强制停止服务器进程" -ForegroundColor Red
    Write-Host "  5. 显示帮助" -ForegroundColor Gray
    Write-Host "  6. 退出" -ForegroundColor Gray
    Write-Host ""
    Write-Host "认证信息:" -ForegroundColor White
    Write-Host "  用户名: admin (可配置)" -ForegroundColor Gray
    Write-Host "  密码: 基于时间 (yyyymmddHHMM 格式，5分钟内有效)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "系统要求:" -ForegroundColor White
    Write-Host "  - Python 3.x 已安装并添加到 PATH" -ForegroundColor Gray
    Write-Host "  - PowerShell 5.0+ 或 CMD" -ForegroundColor Gray
    Write-Host ""
    Write-Host "支持的系统:" -ForegroundColor White
    Write-Host "  - Windows 10/11" -ForegroundColor Gray
    Write-Host "  - Windows Server 2016+" -ForegroundColor Gray
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
}

# Create desktop shortcut
function Create-DesktopShortcut {
    Write-Host ""
    Write-Host "创建桌面快捷方式..." -ForegroundColor Yellow
    Write-Host ""
    
    # Get current script path
    $CurrentScript = $MyInvocation.MyCommand.Path
    if (-not $CurrentScript) {
        $CurrentScript = Join-Path $ScriptDir "lan-file-server-launcher.ps1"
    }
    
    # Get desktop path
    try {
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $ShortcutPath = Join-Path $DesktopPath "LAN File Server.lnk"
        
        # Create WScript.Shell object
        $WshShell = New-Object -comObject WScript.Shell
        
        # Create shortcut
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        
        # Set shortcut properties
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$CurrentScript`""
        $Shortcut.WorkingDirectory = $ScriptDir
        $Shortcut.Description = "LAN File Server - Local Network File Sharing Service"
        $Shortcut.Save()
        
        Write-ColorOutput "[Success] Desktop shortcut created!" "Green"
        Write-ColorOutput "Location: $ShortcutPath" "Cyan"
        Write-Host ""
        Write-ColorOutput "Shortcut Properties:" "Yellow"
        Write-ColorOutput "  Name: LAN File Server" "White"
        Write-ColorOutput "  Target: $($CurrentScript | Split-Path -Leaf)" "White"
        Write-ColorOutput "  Working Directory: $ScriptDir" "White"
        Write-ColorOutput "  Description: Local network file sharing server" "White"
        
        return $true
    } catch {
        Write-ColorOutput "[Error] Failed to create shortcut: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Start server
function Start-Server {
    Write-Host ""
    Write-Host "启动 LAN 文件服务器..." -ForegroundColor Green
    Write-Host ""
    
    Write-ColorOutput "启动中..." "Yellow"
    Write-ColorOutput "按 Ctrl+C 停止服务器并返回菜单" "Magenta"
    Write-Host ""
    
    # Add note about the enhanced logging system
    Write-Host "🔍 增强日志系统:" -ForegroundColor Cyan
    Write-Host "  ✨ 彩色日志消息，提高可见性" -ForegroundColor White
    Write-Host "  🎨 不同日志级别使用不同颜色（信息、警告、错误）" -ForegroundColor White
    Write-Host "  ⏰ 时间戳记录，便于问题追踪" -ForegroundColor White
    Write-Host ""
    
    try {
        # Set environment variable to disable Python interactive mode
        $env:PYTHONUNBUFFERED = "1"
        
        # Start server
        python server.py
    } catch {
        Write-Host ""
        Write-ColorOutput "[Error] Server startup failed!" "Red"
        Write-ColorOutput "Error: $($_.Exception.Message)" "Yellow"
        Write-Host ""
        Write-ColorOutput "Common solutions:" "Yellow"
        Write-ColorOutput "  1. Check Python installation" "White"
        Write-ColorOutput "  2. Check if port is in use" "White"
        Write-ColorOutput "  3. Check firewall settings" "White"
        Write-ColorOutput "  4. Check server.py for syntax errors" "White"
    } finally {
        Write-Host ""
        Write-ColorOutput "Server stopped. Returning to main menu..." "Green"
        Write-Host ""
    }
}

# Force stop server processes
function Force-Stop-Server {
    Write-Host ""
    Write-Host "强制停止服务器" -ForegroundColor Red
    Write-Host ""
    
    # Get all Python processes
    $pythonProcesses = Get-Process python -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*server.py*" -or $_.CommandLine -like "*lan-file-server*"
    }
    
    if ($pythonProcesses.Count -eq 0) {
        Write-ColorOutput "[Info] No server processes found running." "Green"
        Write-ColorOutput "All server processes are already stopped." "Green"
        return
    }
    
    Write-ColorOutput "Found $($pythonProcesses.Count) server process(es):" "Yellow"
    Write-Host ""
    
    $index = 1
    foreach ($process in $pythonProcesses) {
        Write-ColorOutput "[$index] PID: $($process.Id)" "White"
        Write-ColorOutput "    Process Name: $($process.ProcessName)" "White"
        Write-ColorOutput "    Start Time: $($process.StartTime)" "White"
        Write-ColorOutput "    CPU Usage: $([math]::Round($process.CPU, 2))s" "White"
        Write-ColorOutput "    Memory Usage: $([math]::Round($process.WorkingSet64 / 1MB, 2))MB" "White"
        Write-Host ""
        $index++
    }
    
    Write-Host ""
    Write-ColorOutput "Choose action:" "Yellow"
    Write-ColorOutput "  A. Stop ALL server processes" "Red"
    Write-ColorOutput "  Q. Quit (do nothing)" "Gray"
    Write-Host ""
    
    $choice = Read-Host "Enter your choice"
    
    switch ($choice.ToUpper()) {
        "A" {
            Write-Host ""
            Write-ColorOutput "WARNING: This will stop ALL server processes!" "Red"
            $confirm = Read-Host "Are you sure? (y/N)"
            if ($confirm -eq "Y" -or $confirm -eq "y") {
                Write-Host ""
                Write-ColorOutput "Stopping all server processes..." "Yellow"
                
                $successCount = 0
                $failCount = 0
                
                foreach ($process in $pythonProcesses) {
                    try {
                        Write-ColorOutput "Stopping PID: $($process.Id)" "Cyan"
                        
                        # First try graceful shutdown
                        $process.CloseMainWindow()
                        Start-Sleep -Seconds 2
                        
                        # Check if process is still running
                        if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
                            $process.Kill()
                            Start-Sleep -Seconds 1
                        }
                        
                        # Verify process is stopped
                        if (-not (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) {
                            Write-ColorOutput "[Success] PID $($process.Id) stopped!" "Green"
                            $successCount++
                        } else {
                            Write-ColorOutput "[Error] Failed to stop PID $($process.Id)" "Red"
                            $failCount++
                        }
                    } catch {
                        Write-ColorOutput "[Error] Failed to stop PID $($process.Id): $($_.Exception.Message)" "Red"
                        $failCount++
                    }
                }
                
                Write-Host ""
                Write-ColorOutput "=== Stop Summary ===" "Cyan"
                Write-ColorOutput "Successfully stopped: $successCount process(es)" "Green"
                if ($failCount -gt 0) {
                    Write-ColorOutput "Failed to stop: $failCount process(es)" "Red"
                }
            } else {
                Write-ColorOutput "Operation cancelled." "Yellow"
            }
        }
        "Q" {
            Write-ColorOutput "Operation cancelled." "Yellow"
        }
        default {
            Write-ColorOutput "[Error] Invalid choice!" "Red"
        }
    }
}

# Test Python environment
function Test-PythonEnvironment {
    try {
        $pythonVersion = python --version 2>&1
        return $true
    } catch {
        return $false
    }
}

# Test server file
function Test-ServerFile {
    return Test-Path "server.py"
}

# Test configuration
function Test-Configuration {
    if (Test-Path "config.py") {
        Write-ColorOutput "[Info] Config file found: config.py" "Green"
    } elseif (Test-Path "config.json") {
        Write-ColorOutput "[Info] Config file found: config.json" "Green"
    } else {
        Write-ColorOutput "[Warning] No config file found, using defaults" "Yellow"
    }
}

# Main program logic
function Main {
    # Handle command line arguments first
    if ($Help) {
        Show-Help
        return
    }
    
    # if ($Initialize) {
    #     Initialize-Server
    #     return
    # }
    
    if ($CreateShortcut) {
        $success = Create-DesktopShortcut
        if ($success) {
            Write-Host ""
            Write-ColorOutput "Double-click 'LAN File Server' shortcut on desktop to start server" "Cyan"
        }
        return
    }
    
    # Run initial checks
    if (-not (Test-PythonEnvironment)) {
        Write-Host ""
        Write-ColorOutput "[Error] Python not found!" "Red"
        Write-ColorOutput "Please install Python 3.x and add to PATH" "Yellow"
        Write-ColorOutput "Download: https://www.python.org/downloads/" "Yellow"
        Write-Host ""
        Read-Host "Press any key to exit"
        return
    }
    
    if (-not (Test-ServerFile)) {
        Write-Host ""
        Write-ColorOutput "[Error] server.py not found!" "Red"
        Write-ColorOutput "Please run this script in the correct project directory" "Yellow"
        Write-Host ""
        Read-Host "Press any key to exit"
        return
    }
    
    $exitScript = $false
    
    while (-not $exitScript) {
        # Show startup interface
        Write-Host ""
        Write-Host "LAN File Server Launcher" -ForegroundColor Cyan
        Write-Host "Version: 1.0.0" -ForegroundColor Cyan
        Write-Host ""
        
        Test-Configuration
        
        # Offer options
        Write-Host ""
        Write-Host " 1. 启动服务器" -ForegroundColor Green
        # Write-Host "⚙️ 2. 初始化服务器配置" -ForegroundColor Yellow
        Write-Host " 3. 创建桌面快捷方式" -ForegroundColor Magenta
        Write-Host " 4. 强制停止服务器进程" -ForegroundColor Red
        Write-Host " 5. 显示帮助" -ForegroundColor Cyan
        Write-Host " 6. 退出" -ForegroundColor Gray
        Write-Host ""
        
        # 循环输入，直到用户提供有效选项
        $validInput = $false
        while (-not $validInput) {
            $choice = Read-Host "Enter choice (1,3,4,5,6)"
            
            # 检查输入是否有效
            if ($choice -in @("1","3","4","5","6")) {
                $validInput = $true
                
                switch ($choice) {
                    "1" {
                        Write-Host "正在启动服务器..." -ForegroundColor Green
                        Start-Server
                        Write-Host ""
                        Write-Host "服务器已停止，返回主菜单" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "按任意键返回主菜单..." -ForegroundColor Yellow
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                    "3" {
                        Write-Host "正在创建桌面快捷方式..." -ForegroundColor Magenta
                        Create-DesktopShortcut
                        Write-Host ""
                        Write-Host "创建完成，按任意键返回主菜单..." -ForegroundColor Cyan
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                    "4" {
                        Write-Host "正在检查服务器进程..." -ForegroundColor Red
                        Force-Stop-Server
                        Write-Host ""
                        Write-Host "操作完成，按任意键返回主菜单..." -ForegroundColor Cyan
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                    "5" {
                        Write-Host "正在显示帮助信息..." -ForegroundColor Cyan
                        Show-Help
                        Write-Host ""
                        Write-Host "帮助显示完成，按任意键返回主菜单..." -ForegroundColor Cyan
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                    "6" {
                        Write-Host "正在退出..." -ForegroundColor Gray
                        Write-Host "感谢使用 LAN 文件服务器!" -ForegroundColor Cyan
                        Write-Host ""
                        $exitScript = $true
                    }
                }
            } else {
                # 显示中文错误提示
                Write-Host ""
                Write-ColorOutput "[错误] 无效的输入！请输入有效的选项。" "Red"
                Write-ColorOutput "有效选项：1, 3, 4, 5, 6" "White"
                Write-Host ""
                Write-ColorOutput "请重新输入：" "Yellow"
            }
        }
    }
}

# Execute main program
try {
    Main
} catch {
    Write-ColorOutput "[Critical Error] Program execution error!" "Red"
    Write-ColorOutput "Error: $($_.Exception.Message)" "Yellow"
    Write-Host ""
    Read-Host "Press any key to exit"
} finally {
    # Restore original directory
    Set-Location $OriginalDir
}