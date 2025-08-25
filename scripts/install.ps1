# Security Monitoring Dashboard Installation Script
# Run as Administrator

param(
    [switch]$InstallPython,
    [switch]$InstallSQLServer,
    [switch]$SetupDatabase,
    [switch]$InstallService
)

Write-Host "Security Monitoring Dashboard - Installation Script" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot

# Install Python if requested
if ($InstallPython) {
    Write-Host "Installing Python..." -ForegroundColor Yellow
    
    # Check if Python is already installed
    try {
        $pythonVersion = python --version 2>$null
        Write-Host "Python already installed: $pythonVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "Python not found. Please install Python 3.8+ manually." -ForegroundColor Red
        Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
        exit 1
    }
}

# Install Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
Set-Location $ProjectRoot

try {
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    Write-Host "Python dependencies installed successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to install Python dependencies: $_"
    exit 1
}

# Install SQL Server Express if requested
if ($InstallSQLServer) {
    Write-Host "Installing SQL Server Express..." -ForegroundColor Yellow
    
    $sqlExpressUrl = "https://download.microsoft.com/download/7/c/1/7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLEXPR_x64_ENU.exe"
    $sqlExpressPath = "$env:TEMP\SQLEXPR_x64_ENU.exe"
    
    # Download SQL Server Express
    Invoke-WebRequest -Uri $sqlExpressUrl -OutFile $sqlExpressPath
    
    # Install silently
    Start-Process -FilePath $sqlExpressPath -ArgumentList "/Q", "/IACCEPTSQLSERVERLICENSETERMS", "/ACTION=Install", "/FEATURES=SQLEngine", "/INSTANCENAME=SQLEXPRESS" -Wait
    
    Write-Host "SQL Server Express installation completed" -ForegroundColor Green
}

# Setup database
if ($SetupDatabase) {
    Write-Host "Setting up database..." -ForegroundColor Yellow
    
    try {
        # Run database setup script
        sqlcmd -S "localhost\SQLEXPRESS" -i "$ProjectRoot\src\database\setup.sql"
        
        # Create tables using Python
        python -c "from src.database.database import db_manager; db_manager.create_tables()"
        
        Write-Host "Database setup completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Database setup failed: $_"
        exit 1
    }
}

# Install as Windows service
if ($InstallService) {
    Write-Host "Installing Windows service..." -ForegroundColor Yellow
    
    $serviceName = "SecurityMonitoringDashboard"
    $serviceDisplayName = "Security Monitoring Dashboard"
    $serviceDescription = "Real-time security monitoring and threat detection system"
    $pythonPath = (Get-Command python).Source
    $scriptPath = "$ProjectRoot\main.py"
    
    # Create service using sc.exe
    $serviceCommand = "`"$pythonPath`" `"$scriptPath`" --daemon"
    
    sc.exe create $serviceName binPath= $serviceCommand DisplayName= $serviceDisplayName type= own start= auto
    sc.exe description $serviceName $serviceDescription
    
    Write-Host "Service installed. Use 'sc start $serviceName' to start the service." -ForegroundColor Green
}

# Create startup script
$startupScript = @"
@echo off
cd /d "$ProjectRoot"
python main.py --daemon
pause
"@

$startupScript | Out-File -FilePath "$ProjectRoot\start_monitoring.bat" -Encoding ascii

# Create configuration template
if (-not (Test-Path "$ProjectRoot\.env")) {
    Copy-Item "$ProjectRoot\.env.example" "$ProjectRoot\.env"
    Write-Host "Configuration template created at .env - please update with your settings" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Update .env file with your database and SMTP settings"
Write-Host "2. Run initial setup: python main.py --setup"
Write-Host "3. Start monitoring: python main.py --daemon"
Write-Host ""
Write-Host "For help: python main.py --help" -ForegroundColor Cyan