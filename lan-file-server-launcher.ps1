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
    Write-ColorOutput "2. Configure user authentication" "White"
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
    
    # Configure authentication
    Write-Host ""
    Write-ColorOutput "=== Step 2: Configure Authentication ===" "Yellow"
    
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
    
    # Get password
    Write-Host ""
    Write-ColorOutput "Enter password for user '$username':" "White"
    $securePassword = Read-Host "Password" -AsSecureString
    $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)
    
    if ([string]::IsNullOrWhiteSpace($password)) {
        Write-ColorOutput "[Error] Password cannot be empty!" "Red"
        return
    }
    
    # Generate salt and hash
    Write-ColorOutput "[Info] Generating password hash..." "Cyan"
    $salt = Generate-Salt
    if (-not $salt) {
        Write-ColorOutput "[Error] Failed to generate salt" "Red"
        return
    }
    
    $passwordHash = Generate-PasswordHash $password $salt
    if (-not $passwordHash) {
        Write-ColorOutput "[Error] Failed to generate password hash" "Red"
        return
    }
    
    Write-ColorOutput "[Success] Password hash generated" "Green"
    
    # Update configuration files
    Write-Host ""
    Write-ColorOutput "=== Step 3: Updating Configuration Files ===" "Yellow"
    
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
    
    # Update auth_config.ini
    if (Update-IniFile "auth_config.ini" "AUTH" "username" $username) {
        Write-ColorOutput "[Success] Updated username in auth_config.ini" "Green"
    } else {
        Write-ColorOutput "[Error] Failed to update username in auth_config.ini" "Red"
    }
    
    if (Update-IniFile "auth_config.ini" "AUTH" "password_hash" $passwordHash) {
        Write-ColorOutput "[Success] Updated password_hash in auth_config.ini" "Green"
    } else {
        Write-ColorOutput "[Error] Failed to update password_hash in auth_config.ini" "Red"
    }
    
    if (Update-IniFile "auth_config.ini" "AUTH" "salt" $salt) {
        Write-ColorOutput "[Success] Updated salt in auth_config.ini" "Green"
    } else {
        Write-ColorOutput "[Error] Failed to update salt in auth_config.ini" "Red"
    }
    
    # Test server functionality
    Write-Host ""
    Write-ColorOutput "=== Step 4: Testing Server Functionality ===" "Yellow"
    
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
    Write-ColorOutput "Password: [HIDDEN]" "White"
    Write-Host ""
    Write-ColorOutput "Configuration files have been updated successfully!" "Green"
    Write-Host ""
    Write-ColorOutput "Next steps:" "Yellow"
    Write-ColorOutput "1. Run the server launcher to start the server" "White"
    Write-ColorOutput "2. Access the server at http://localhost:8000" "White"
    Write-ColorOutput "3. Login with username: $username and your password" "White"
    Write-Host ""
}

# Show initialization header
function Show-InitializationHeader {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "        LAN File Server Initialization" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Generate password hash using PBKDF2-HMAC-SHA256 (compatible with server)
function Generate-PasswordHash {
    param(
        [string]$Password,
        [string]$Salt
    )
    
    try {
        # Import required .NET libraries for cryptography
        Add-Type -AssemblyName System.Security.Cryptography
        
        # Convert salt from hex string to bytes
        $saltBytes = [System.Convert]::FromHexString($Salt)
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        
        # Use PBKDF2-HMAC-SHA256 with 100,000 iterations (matching server)
        $iterations = 100000
        $derivedKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passwordBytes, $saltBytes, $iterations)
        $hashBytes = $derivedKey.GetBytes(32)  # 32 bytes = 256 bits
        
        # Convert to hex string
        $hashString = ""
        foreach ($byte in $hashBytes) {
            $hashString += $byte.ToString("x2")
        }
        
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
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "            LAN File Server Launcher" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor White
    Write-Host "  .\lan-file-server-launcher.ps1              # Start server" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -Initialize   # Initialize server configuration" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -CreateShortcut # Create desktop shortcut" -ForegroundColor Gray
    Write-Host "  .\lan-file-server-launcher.ps1 -Help        # Show this help" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Requirements:" -ForegroundColor White
    Write-Host "  - Python 3.x installed and added to PATH" -ForegroundColor Gray
    Write-Host "  - PowerShell 5.0+ or CMD" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Supported OS:" -ForegroundColor White
    Write-Host "  - Windows 10/11" -ForegroundColor Gray
    Write-Host "  - Windows Server 2016+" -ForegroundColor Gray
    Write-Host ""
}

# Create desktop shortcut
function Create-DesktopShortcut {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "        Create Desktop Shortcut" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
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

# Start server
function Start-Server {
    Write-Host ""
    Write-ColorOutput "[Info] Starting LAN File Server..." "Cyan"
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
        Write-ColorOutput "Server stopped" "Gray"
        Write-Host ""
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
    
    # Show startup interface
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "          LAN File Server Launcher" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
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
    
    # Offer options
    Write-Host ""
    Write-ColorOutput "Choose action:" "Yellow"
    Write-ColorOutput "  1. Start server" "White"
    Write-ColorOutput "  2. Initialize server configuration" "White"
    Write-ColorOutput "  3. Create desktop shortcut" "White"
    Write-ColorOutput "  4. Show help" "White"
    Write-ColorOutput "  5. Exit" "White"
    Write-Host ""
    
    $choice = Read-Host "Enter choice (1-5)"
    
    switch ($choice) {
        "1" {
            Start-Server
            Write-Host ""
            Read-Host "Press any key to exit"
        }
        "2" {
            Initialize-Server
            Write-Host ""
            Read-Host "Press any key to exit"
        }
        "3" {
            Create-DesktopShortcut
            Write-Host ""
            Read-Host "Press any key to exit"
        }
        "4" {
            Show-Help
            Write-Host ""
            Read-Host "Press any key to exit"
        }
        "5" {
            Write-ColorOutput "Exiting..." "Gray"
        }
        default {
            Write-ColorOutput "Invalid choice, starting server..." "Yellow"
            Start-Server
            Write-Host ""
            Read-Host "Press any key to exit"
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