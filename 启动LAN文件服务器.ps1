# LAN文件服务器启动脚本
# PowerShell版本

# 设置控制台编码为UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 设置窗口标题
$Host.UI.RawUI.WindowTitle = "LAN文件服务器"

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "          LAN文件服务器启动器" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# 获取脚本所在目录
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 检查Python是否安装
try {
    $pythonVersion = python --version 2>$null
    Write-Host "[信息] 检测到Python版本: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[错误] 未检测到Python环境！" -ForegroundColor Red
    Write-Host "请确保已安装Python并添加到PATH环境变量" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "按任意键退出"
    exit 1
}

# 检查server.py是否存在
if (-not (Test-Path "server.py")) {
    Write-Host "[错误] 未找到server.py文件！" -ForegroundColor Red
    Write-Host "请确保在正确的目录下运行此脚本" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "按任意键退出"
    exit 1
}

# 检查配置文件
if (Test-Path "server_config.ini") {
    Write-Host "[信息] 找到配置文件: server_config.ini" -ForegroundColor Green
} else {
    Write-Host "[警告] 未找到配置文件，将使用默认设置" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[信息] 正在启动LAN文件服务器..." -ForegroundColor Cyan
Write-Host ""

# 启动服务器
try {
    python server.py
} catch {
    Write-Host ""
    Write-Host "[错误] 服务器启动失败！" -ForegroundColor Red
    Write-Host "错误信息: $($_.Exception.Message)" -ForegroundColor Yellow
} finally {
    Write-Host ""
    Write-Host "服务器已关闭" -ForegroundColor Gray
    Read-Host "按任意键退出"
}