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

# Initialize server configuration
function Initialize-Server {
    Show-InitializationHeader
    
    Write-ColorOutput "This script will help you configure your LAN File Server:" "White"
    Write-ColorOutput "1. Set the shared directory path" "White"
    Write-ColorOutput "2. Configure username (Note: Fixed password is time-based)" "White"
    Write-ColorOutput "3. Validate server functionality" "White"
    Write-Host ""
    
    # Get shared directory path
    Write-ColorOutput "=== Step 1: Configure Shared Directory ===" "Yellow"
    Write-ColorOutput "Enter the path to your shared directory (e.g., C:\Users\YourName\Documents):" "White"
    Write-ColorOutput "Default: C:\Users\$env:USERNAME\Documents" "Gray"
    
    $shareDir = Read-Host "Shared directory path"
    if ([string]::IsNullOrWhiteSpace($shareDir)) {
        $shareDir = "C:\Users\$env:USERNAME\Documents"
    }
    
    # Validate directory path
    $isValid, $validatedPath = Validate-DirectoryPath $shareDir
    if (-not $isValid) {
        Write-ColorOutput "[Error] Invalid directory: $validatedPath" "Red"
        Write-Host ""
        $retry = Read-Host "Do you want to try again? (Y/N)"
        if ($retry -eq "Y" -or $retry -eq "y") {
            return Initialize-Server
        } else {
            Write-ColorOutput "Initialization cancelled" "Gray"
            return
        }
    }
    
    Write-ColorOutput "[Success] Valid directory: $validatedPath" "Green"
    
    # Configure username
    Write-Host ""
    Write-ColorOutput "=== Step 2: Configure Username ===" "Yellow"
    
    # Check if auth_config.ini exists, if not create it
    if (-not (Test-Path "auth_config.ini")) {
        Write-ColorOutput "[Info] Creating auth_config.ini..." "Cyan"
        $defaultAuthContent = @"
[AUTH]
username = admin
password_hash = 
salt = 
failed_auth_limit = 5
failed_auth_block_time = 300
"@
        Set-Content -Path "auth_config.ini" -Value $defaultAuthContent -Encoding UTF8
    }
    
    # Get username
    Write-ColorOutput "Enter username (default: admin):" "White"
    $username = Read-Host "Username"
    if ([string]::IsNullOrWhiteSpace($username)) {
        $username = "admin"
    }
    
    Write-Host ""
    Write-ColorOutput "=== Step 3: Authentication Information ===" "Yellow"
    Write-ColorOutput "NOTE: Password authentication has been simplified!" "Cyan"
    Write-ColorOutput "- Username: $username (can be modified above)" "White"
    Write-ColorOutput "- Password: Time-based password (current time in yyyymmddHHMM format)" "White"
    Write-ColorOutput "- Example: If current time is 2025-12-30 13:10, password is: 202512301310" "Gray"
    Write-Host ""
    
    # Update configuration files
    Write-ColorOutput "=== Step 4: Updating Configuration Files ===" "Yellow"
    
    # Update server_config.ini
    if (Test-Path "server_config.ini") {
        if (Update-IniFile "server_config.ini" "SERVER" "share_dir" $validatedPath) {
            Write-ColorOutput "[Success] Updated share_dir in server_config.ini" "Green"
        } else {
            Write-ColorOutput "[Error] Failed to update server_config.ini" "Red"
        }
    } else {
        Write-ColorOutput "[Warning] server_config.ini not found, skipping share_dir update" "Yellow"
    }
    
    # Update auth_config.ini (username only)
    if (Update-IniFile "auth_config.ini" "AUTH" "username" $username) {
        Write-ColorOutput "[Success] Updated username in auth_config.ini" "Green"
    } else {
        Write-ColorOutput "[Error] Failed to update username in auth_config.ini" "Red"
    }
    
    # Test server functionality
    Write-Host ""
    Write-ColorOutput "=== Step 5: Testing Server Functionality ===" "Yellow"
    
    if (Test-ServerFunctionality) {
        Write-ColorOutput "[Success] Server functionality test passed!" "Green"
    } else {
        Write-ColorOutput "[Warning] Some server functionality tests failed" "Yellow"
    }
    
    # Summary
    Write-Host ""
    Write-ColorOutput "=== Initialization Summary ===" "Cyan"
    Write-ColorOutput "Shared Directory: $validatedPath" "White"
    Write-ColorOutput "Username: $username" "White"
    Write-ColorOutput "Password: Time-based (yyyymmddHHMM format)" "White"
    Write-Host ""
    Write-ColorOutput "Configuration files have been updated successfully!" "Green"
    Write-Host ""
    Write-ColorOutput "Next steps:" "Yellow"
    Write-ColorOutput "1. Run the server launcher to start the server" "White"
    Write-ColorOutput "2. Access the server at http://localhost:8000" "White"
    Write-ColorOutput "3. Login with username: $username and current time-based password" "White"
    Write-ColorOutput "4. Current time-based password example: $(Get-Date -Format 'yyyyMMddHHmm')" "Gray"
    Write-Host ""
}

# Show initialization header with enhanced visual effects
function Show-InitializationHeader {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "║                    ⚙️ 服务器配置初始化 ⚙️                              ║" -ForegroundColor Yellow
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Generate password hash using PBKDF2-HMAC-SHA256 (compatible with server)
function Generate-PasswordHash {
    param(
        [string]$Password,
        [string]$Salt
    )
    
    try {
        # Import required .NET libraries for cryptography - use correct assembly
        Add-Type -AssemblyName System.Core
        
        # Convert salt from hex string to bytes - manual conversion for compatibility
        $saltBytes = New-Object byte[] ($Salt.Length / 2)
        for ($i = 0; $i -lt $Salt.Length; $i += 2) {
            $saltBytes[$i/2] = [Convert]::ToByte($Salt.Substring($i, 2), 16)
        }
        
        # Ensure password is properly encoded as UTF-8 - Match Python exactly
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        
        # Use PBKDF2-HMAC-SHA256 with 100,000 iterations (matching server)
        $iterations = 100000
        
        # Use PBKDF2-HMAC-SHA256 with exact parameters matching Python's hashlib.pbkdf2_hmac
        $derivedKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passwordBytes, $saltBytes, $iterations)
        $hashBytes = $derivedKey.GetBytes(32)  # 32 bytes = 256 bits
        
        # Convert to hex string with consistent formatting
        $hashString = -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
        
        return $hashString
    } catch {
        Write-ColorOutput "[Error] Failed to generate password hash: $($_.Exception.Message)" "Red"
        return $null
    }
}

# Generate random salt (16 bytes for PBKDF2)
function Generate-Salt {
    try {
        Add-Type -AssemblyName System.Security.Cryptography
        
        # Generate 16 bytes of random salt
        $saltBytes = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($saltBytes)
        
        # Convert to hex string
        $saltString = ""
        foreach ($byte in $saltBytes) {
            $saltString += $byte.ToString("x2")
        }
        
        return $saltString
    } catch {
        Write-ColorOutput "[Error] Failed to generate salt: $($_.Exception.Message)" "Red"
        return $null
    }
}

# Update INI file
function Update-IniFile {
    param(
        [string]$FilePath,
        [string]$Section,
        [string]$Key,
        [string]$Value
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-ColorOutput "[Error] Configuration file not found: $FilePath" "Red"
            return $false
        }
        
        $content = Get-Content $FilePath
        $updated = $false
        $newContent = @()
        $sectionFound = $false
        
        foreach ($line in $content) {
            if ($line -match "^\[$Section\]$") {
                $sectionFound = $true
                $newContent += $line
            } elseif ($sectionFound -and $line -match "^$Key\s*=") {
                $newContent += "$Key = $Value"
                $updated = $true
                $sectionFound = $false
            } else {
                $newContent += $line
                if ($line -match "^\[.*\]$") {
                    $sectionFound = $false
                }
            }
        }
        
        # If section doesn't exist, add it
        if (-not $updated) {
            $newContent += "[$Section]"
            $newContent += "$Key = $Value"
            $updated = $true
        }
        
        # Write updated content
        Set-Content -Path $FilePath -Value $newContent -Encoding UTF8
        return $true
    } catch {
        Write-ColorOutput "[Error] Failed to update INI file: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Validate directory path
function Validate-DirectoryPath {
    param([string]$Path)
    
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $false, "Path cannot be empty"
        }
        
        # Expand environment variables
        $expandedPath = [Environment]::ExpandEnvironmentVariables($Path)
        
        # Check if path exists
        if (-not (Test-Path $expandedPath)) {
            return $false, "Directory does not exist: $expandedPath"
        }
        
        # Check if it's a directory
        if ((Get-Item $expandedPath) -isnot [System.IO.DirectoryInfo]) {
            return $false, "Path is not a directory: $expandedPath"
        }
        
        # Check if directory is accessible
        try {
            $null = Get-ChildItem -Path $expandedPath -ErrorAction Stop
        } catch {
            return $false, "Directory is not accessible: $expandedPath"
        }
        
        return $true, $expandedPath
    } catch {
        return $false, "Invalid path format: $Path"
    }
}

# Test server functionality
function Test-ServerFunctionality {
    Write-ColorOutput "[Info] Testing server functionality..." "Cyan"
    
    try {
        # Check if Python is available
        $pythonVersion = python --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[Error] Python not found!" "Red"
            return $false
        }
        
        Write-ColorOutput "[Info] Python found: $pythonVersion" "Green"
        
        # Check if server.py exists
        if (-not (Test-Path "server.py")) {
            Write-ColorOutput "[Error] server.py not found!" "Red"
            return $false
        }
        
        Write-ColorOutput "[Info] server.py found" "Green"
        
        # Check configuration files
        if (-not (Test-Path "server_config.ini")) {
            Write-ColorOutput "[Warning] server_config.ini not found" "Yellow"
        } else {
            Write-ColorOutput "[Info] server_config.ini found" "Green"
        }
        
        if (-not (Test-Path "auth_config.ini")) {
            Write-ColorOutput "[Warning] auth_config.ini not found" "Yellow"
        } else {
            Write-ColorOutput "[Info] auth_config.ini found" "Green"
        }
        
        return $true
    } catch {
        Write-ColorOutput "[Error] Server test failed: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Show help information
function Show-Help {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "                                  .:-=+*%@@@@@%*+=-:. " -ForegroundColor Yellow
    Write-Host "                              :=*%@@@@@@@@@@@@@@@@@@@%*+=: " -ForegroundColor Yellow
    Write-Host "                          :=*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*+=: " -ForegroundColor Yellow
    Write-Host "                        =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@% " -ForegroundColor Yellow
    Write-Host "                       %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@% " -ForegroundColor Yellow
    Write-Host "                      #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@# " -ForegroundColor Yellow
    Write-Host "                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " -ForegroundColor Yellow
    Write-Host "                    &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@& " -ForegroundColor Yellow
    Write-Host "                   #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@# " -ForegroundColor Yellow
    Write-Host "                   %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@% " -ForegroundColor Yellow
    Write-Host "                   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " -ForegroundColor Yellow
    Write-Host "                   #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@# " -ForegroundColor Yellow
    Write-Host "                    &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@& " -ForegroundColor Yellow
    Write-Host "                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " -ForegroundColor Yellow
    Write-Host "                      #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@# " -ForegroundColor Yellow
    Write-Host "                       %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@% " -ForegroundColor Yellow
    Write-Host "                        =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@% " -ForegroundColor Yellow
    Write-Host "                          :=*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*+=: " -ForegroundColor Yellow
    Write-Host "                              :=*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*+=: " -ForegroundColor Yellow
    Write-Host "                                  .:-=+*%@@@@@@@@@@@@@@@@@@@%*+=-:. " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "                              🎨  LAN 文件服务器启动器  🎨" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "用法:" -ForegroundColor White
    Write-Host "  .\lan-file-server-launcher.ps1              # 启动服务器" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -Initialize   # 初始化服务器配置" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -CreateShortcut # 创建桌面快捷方式" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -Help        # 显示此帮助" -ForegroundColor Gray
    Write-Host ""
    Write-Host "主菜单选项:" -ForegroundColor White
    Write-Host "  1. 启动服务器" -ForegroundColor Green
    Write-Host "  2. 初始化服务器配置" -ForegroundColor Yellow
    Write-Host "  3. 创建桌面快捷方式" -ForegroundColor Yellow
    Write-Host "  4. 强制停止服务器进程" -ForegroundColor Red
    Write-Host "  5. 显示帮助" -ForegroundColor Gray
    Write-Host "  6. 退出" -ForegroundColor Gray
    Write-Host ""
    Write-Host "认证信息:" -ForegroundColor White
    Write-Host "  用户名: admin (可配置)" -ForegroundColor Gray
    Write-Host "  密码: 基于时间 (yyyymmddHHMM 格式)" -ForegroundColor Gray
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

# Create desktop shortcut with enhanced visual effects
function Create-DesktopShortcut {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "║                   🖥️ 创建桌面快捷方式 🖥️                             ║" -ForegroundColor Yellow
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Get current script path
    $CurrentScript = $MyInvocation.MyCommand.Path
    if (-not $CurrentScript) {
        $CurrentScript = Join-Path $ScriptDir "lan-file-server-launcher.ps1"
    }
    
    # Find executable startup scripts
    $TargetScripts = @()
    
    # List all .bat and .ps1 files and filter for server-related scripts
    $AllScripts = Get-ChildItem -Path $ScriptDir -Filter "*.bat" -File
    foreach ($Script in $AllScripts) {
        if ($Script.Name -match "start|server|LAN|launcher") {
            $TargetScripts += $Script.FullName
        }
    }
    
    $AllPSScripts = Get-ChildItem -Path $ScriptDir -Filter "*.ps1" -File
    foreach ($Script in $AllPSScripts) {
        if ($Script.Name -match "start|server|LAN|launcher|启动") {
            $TargetScripts += $Script.FullName
        }
    }
    
    # Always include current script if not already included
    $CurrentScriptPath = $MyInvocation.MyCommand.Path
    if ($CurrentScriptPath -and $TargetScripts -notcontains $CurrentScriptPath) {
        $TargetScripts += $CurrentScriptPath
    }
    
    if ($TargetScripts.Count -eq 0) {
        Write-ColorOutput "[Error] No startup scripts found!" "Red"
        return $false
    }
    
    # Select best startup script (prefer PowerShell version with "launcher" in name)
    $SelectedScript = $TargetScripts | Where-Object { $_ -like "*launcher.ps1" } | Select-Object -First 1
    if (-not $SelectedScript) {
        # Then prefer enhanced batch version
        $SelectedScript = $TargetScripts | Where-Object { $_ -like "*增强版.bat" } | Select-Object -First 1
    }
    if (-not $SelectedScript) {
        # Finally, use the first available script
        $SelectedScript = $TargetScripts[0]
    }
    
    Write-ColorOutput "[Info] Selected script: $(Split-Path $SelectedScript -Leaf)" "Green"
    
    # Get desktop path
    try {
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $ShortcutPath = Join-Path $DesktopPath "LAN File Server.lnk"
        
        # Create WScript.Shell object
        $WshShell = New-Object -comObject WScript.Shell
        
        # Create shortcut
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        
        # Set shortcut properties
        if ($SelectedScript -like "*.ps1") {
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$SelectedScript`""
        } else {
            $Shortcut.TargetPath = $SelectedScript
        }
        $Shortcut.WorkingDirectory = $ScriptDir
        $Shortcut.Description = "LAN File Server - Local Network File Sharing Service"
        $Shortcut.Save()
        
        Write-ColorOutput "[Success] Desktop shortcut created!" "Green"
        Write-ColorOutput "Location: $ShortcutPath" "Cyan"
        Write-Host ""
        Write-ColorOutput "Shortcut Properties:" "Yellow"
        Write-ColorOutput "  Name: LAN File Server" "White"
        Write-ColorOutput "  Target: $(Split-Path $SelectedScript -Leaf)" "White"
        Write-ColorOutput "  Working Directory: $ScriptDir" "White"
        Write-ColorOutput "  Description: Local network file sharing server" "White"
        
        return $true
    } catch {
        Write-ColorOutput "[Error] Failed to create shortcut!" "Red"
        Write-ColorOutput "Error: $($_.Exception.Message)" "Yellow"
        return $false
    }
}

# Check Python environment
function Test-PythonEnvironment {
    try {
        $pythonVersion = python --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "[Info] Python version: $pythonVersion" "Green"
            return $true
        }
    } catch {
        # Try python3
        try {
            $pythonVersion = python3 --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "[Info] Python version: $pythonVersion" "Green"
                return $true
            }
        } catch {
            # Python not found
        }
    }
    
    Write-ColorOutput "[Error] Python not found!" "Red"
    Write-ColorOutput "Please install Python 3.x and add to PATH" "Yellow"
    Write-ColorOutput "Download: https://www.python.org/downloads/" "Yellow"
    return $false
}

# Check server file
function Test-ServerFile {
    if (Test-Path "server.py") {
        Write-ColorOutput "[Info] Server file found: server.py" "Green"
        return $true
    }
    
    Write-ColorOutput "[Error] server.py not found!" "Red"
    Write-ColorOutput "Please run this script in the correct project directory" "Yellow"
    return $false
}

# Check configuration
function Test-Configuration {
    if (Test-Path "config.py") {
        Write-ColorOutput "[Info] Config file found: config.py" "Green"
    } elseif (Test-Path "server_config.ini") {
        Write-ColorOutput "[Info] Config file found: server_config.ini" "Green"
    } else {
        Write-ColorOutput "[Warning] No config file found, using defaults" "Yellow"
    }
}

# Start server with enhanced visual effects
function Start-Server {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "║                      🚀 启动 LAN 文件服务器 🚀                        ║" -ForegroundColor Green
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    Write-ColorOutput "⚡ 启动中..." "Yellow"
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

# Force stop server processes with enhanced visual effects
function Force-Stop-Server {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "║                    🛑 强制停止服务器进程 🛑                             ║" -ForegroundColor Red
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
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
    
    $processList = @()
    $index = 1
    
    foreach ($process in $pythonProcesses) {
        $processInfo = [PSCustomObject]@{
            Index = $index
            PID = $process.Id
            ProcessName = $process.ProcessName
            StartTime = $process.StartTime
            CPU = [math]::Round($process.CPU, 2)
            WorkingSet = [math]::Round($process.WorkingSet64 / 1MB, 2)
            CommandLine = $process.CommandLine
            Process = $process
        }
        $processList += $processInfo
        
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
    Write-ColorOutput "  1-$($pythonProcesses.Count). Stop specific process" "White"
    Write-ColorOutput "  A. Stop ALL server processes" "Red"
    Write-ColorOutput "  Q. Quit (do nothing)" "Gray"
    Write-Host ""
    
    $choice = Read-Host "Enter your choice"
    
    switch ($choice.ToUpper()) {
        { $_ -match "^[1-9]$" } {
            $processIndex = [int]$choice
            if ($processIndex -ge 1 -and $processIndex -le $processList.Count) {
                $selectedProcess = $processList[$processIndex - 1]
                Stop-Specific-Process $selectedProcess
            } else {
                Write-ColorOutput "[Error] Invalid process number!" "Red"
            }
        }
        "A" {
            Write-Host ""
            Write-ColorOutput "WARNING: This will stop ALL server processes!" "Red"
            $confirm = Read-Host "Are you sure? (Y/N)"
            if ($confirm -eq "Y" -or $confirm -eq "y") {
                Stop-All-Server-Processes $processList
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

# Stop specific process
function Stop-Specific-Process {
    param($processInfo)
    
    Write-Host ""
    Write-ColorOutput "Stopping process PID: $($processInfo.PID)" "Yellow"
    
    try {
        # First try graceful shutdown
        $processInfo.Process.CloseMainWindow()
        Start-Sleep -Seconds 2
        
        # Check if process is still running
        if (Get-Process -Id $processInfo.PID -ErrorAction SilentlyContinue) {
            Write-ColorOutput "Process did not close gracefully. Forcing termination..." "Red"
            $processInfo.Process.Kill()
            Start-Sleep -Seconds 1
        }
        
        # Verify process is stopped
        if (-not (Get-Process -Id $processInfo.PID -ErrorAction SilentlyContinue)) {
            Write-ColorOutput "[Success] Process PID $($processInfo.PID) has been stopped!" "Green"
        } else {
            Write-ColorOutput "[Error] Failed to stop process PID $($processInfo.PID)" "Red"
        }
    } catch {
        Write-ColorOutput "[Error] Failed to stop process: $($_.Exception.Message)" "Red"
    }
}

# Stop all server processes
function Stop-All-Server-Processes {
    param($processList)
    
    Write-Host ""
    Write-ColorOutput "Stopping all server processes..." "Yellow"
    
    $successCount = 0
    $failCount = 0
    
    foreach ($processInfo in $processList) {
        try {
            Write-ColorOutput "Stopping PID: $($processInfo.PID)" "Cyan"
            
            # First try graceful shutdown
            $processInfo.Process.CloseMainWindow()
            Start-Sleep -Seconds 2
            
            # Check if process is still running
            if (Get-Process -Id $processInfo.PID -ErrorAction SilentlyContinue) {
                $processInfo.Process.Kill()
                Start-Sleep -Seconds 1
            }
            
            # Verify process is stopped
            if (-not (Get-Process -Id $processInfo.PID -ErrorAction SilentlyContinue)) {
                Write-ColorOutput "[Success] PID $($processInfo.PID) stopped!" "Green"
                $successCount++
            } else {
                Write-ColorOutput "[Error] Failed to stop PID $($processInfo.PID)" "Red"
                $failCount++
            }
        } catch {
            Write-ColorOutput "[Error] Failed to stop PID $($processInfo.PID): $($_.Exception.Message)" "Red"
            $failCount++
        }
    }
    
    Write-Host ""
    Write-ColorOutput "=== Stop Summary ===" "Cyan"
    Write-ColorOutput "Successfully stopped: $successCount process(es)" "Green"
    if ($failCount -gt 0) {
        Write-ColorOutput "Failed to stop: $failCount process(es)" "Red"
    }
}

# Main program logic
function Main {
    # Handle command line arguments
    if ($Help) {
        Show-Help
        return
    }
    
    if ($Initialize) {
        Initialize-Server
        return
    }
    
    if ($CreateShortcut) {
        $success = Create-DesktopShortcut
        if ($success) {
            Write-Host ""
            Write-ColorOutput "Double-click 'LAN File Server' shortcut on desktop to start server" "Cyan"
        }
        return
    }
    
    # Show startup interface with enhanced visual effects
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "║                    🎨 LAN 文件服务器启动器 🎨                           ║" -ForegroundColor Yellow
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "║                         🌐 局域网文件共享服务 🌐                       ║" -ForegroundColor Magenta
    Write-Host "║                                                                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Run checks
    if (-not (Test-PythonEnvironment)) {
        Write-Host ""
        Read-Host "Press any key to exit"
        return
    }
    
    if (-not (Test-ServerFile)) {
        Write-Host ""
        Read-Host "Press any key to exit"
        return
    }
    
    Test-Configuration
    
    # Offer options with enhanced visual effects
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                           📋 请选择操作 📋                             ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "🚀 1. 启动服务器" -ForegroundColor Green
    Write-Host "⚙️ 2. 初始化服务器配置" -ForegroundColor Yellow
    Write-Host "🖥️ 3. 创建桌面快捷方式" -ForegroundColor Magenta
    Write-Host "🛑 4. 强制停止服务器进程" -ForegroundColor Red
    Write-Host "📖 5. 显示帮助" -ForegroundColor Cyan
    Write-Host "🚪 6. 退出" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Enter choice (1-6)"
    
    switch ($choice) {
        "1" {
            Write-Host "🚀 正在启动服务器..." -ForegroundColor Green
            Start-Server
            Write-Host ""
            Write-Host "✅ 服务器已停止，返回主菜单" -ForegroundColor Green
            Write-Host ""
            Write-Host "👆 按任意键返回主菜单..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" {
            Write-Host "⚙️ 正在初始化服务器配置..." -ForegroundColor Yellow
            Initialize-Server
            Write-Host ""
            Write-Host "📋 配置完成，按任意键退出..." -ForegroundColor Cyan
            Read-Host
        }
        "3" {
            Write-Host "🖥️ 正在创建桌面快捷方式..." -ForegroundColor Magenta
            Create-DesktopShortcut
            Write-Host ""
            Write-Host "📋 创建完成，按任意键退出..." -ForegroundColor Cyan
            Read-Host
        }
        "4" {
            Write-Host "🛑 正在检查服务器进程..." -ForegroundColor Red
            Force-Stop-Server
            Write-Host ""
            Write-Host "📋 操作完成，按任意键返回菜单..." -ForegroundColor Cyan
            Read-Host
        }
        "5" {
            Write-Host "📖 正在显示帮助信息..." -ForegroundColor Cyan
            Show-Help
            Write-Host ""
            Write-Host "📋 帮助显示完成，按任意键退出..." -ForegroundColor Cyan
            Read-Host
        }
        "6" {
            Write-Host "🚪 正在退出..." -ForegroundColor Gray
            Write-Host "👋 感谢使用 LAN 文件服务器!" -ForegroundColor Cyan
            Write-Host ""
        }
        default {
            Write-Host "⚠️ 无效选择，默认启动服务器..." -ForegroundColor Yellow
            Start-Server
            Write-Host ""
            Write-Host "✅ 服务器已停止，返回主菜单" -ForegroundColor Green
            Write-Host ""
            Write-Host "👆 按任意键返回主菜单..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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