#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import argparse
from pathlib import Path

def run_command(command, description):
    print(f"Running: {description}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Error: {description} failed")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        return False
    
    print(f"Success: {description}")
    return True

def deploy_production(target_server, username):
    print(f"Deploying to production server: {target_server}")
    
    # Create deployment package
    deployment_files = [
        "src/",
        "config/",
        "requirements.txt",
        "main.py",
        ".env.example"
    ]
    
    # Create temporary deployment directory
    deploy_dir = "deployment_package"
    if os.path.exists(deploy_dir):
        shutil.rmtree(deploy_dir)
    
    os.makedirs(deploy_dir)
    
    # Copy files to deployment directory
    for item in deployment_files:
        if os.path.isdir(item):
            shutil.copytree(item, f"{deploy_dir}/{item}")
        else:
            shutil.copy2(item, deploy_dir)
    
    # Create deployment archive
    archive_name = f"security_monitor_deploy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.make_archive(archive_name, 'zip', deploy_dir)
    
    # Transfer to target server (requires pscp or similar)
    transfer_cmd = f"scp {archive_name}.zip {username}@{target_server}:/tmp/"
    if not run_command(transfer_cmd, "File transfer"):
        return False
    
    # Remote deployment commands
    remote_commands = [
        f"cd /opt && sudo unzip -o /tmp/{archive_name}.zip",
        f"cd /opt/{deploy_dir} && sudo pip3 install -r requirements.txt",
        f"sudo systemctl stop security-monitoring || true",
        f"sudo cp -r /opt/{deploy_dir}/* /opt/security-monitoring/",
        f"sudo systemctl start security-monitoring",
        f"sudo systemctl enable security-monitoring"
    ]
    
    for cmd in remote_commands:
        ssh_cmd = f"ssh {username}@{target_server} '{cmd}'"
        if not run_command(ssh_cmd, f"Remote: {cmd}"):
            return False
    
    # Cleanup
    shutil.rmtree(deploy_dir)
    os.remove(f"{archive_name}.zip")
    
    print("Production deployment completed successfully!")
    return True

def deploy_development():
    print("Setting up development environment...")
    
    # Install development dependencies
    if not run_command("pip install -e .", "Install package in development mode"):
        return False
    
    # Install additional development tools
    dev_requirements = [
        "pytest",
        "pytest-cov",
        "black",
        "flake8",
        "pre-commit"
    ]
    
    for package in dev_requirements:
        if not run_command(f"pip install {package}", f"Install {package}"):
            return False
    
    # Setup pre-commit hooks
    if not run_command("pre-commit install", "Setup pre-commit hooks"):
        print("Warning: pre-commit setup failed, continuing...")
    
    # Create development database
    if not run_command("python -c \"from src.database.database import db_manager; db_manager.create_tables()\"", "Create development database"):
        return False
    
    print("Development environment setup completed!")
    return True

def run_tests():
    print("Running test suite...")
    
    test_commands = [
        ("python -m pytest tests/ -v", "Unit tests"),
        ("python -m pytest tests/ --cov=src --cov-report=html", "Coverage report"),
        ("flake8 src/ --max-line-length=100", "Code style check"),
        ("black --check src/", "Code formatting check")
    ]
    
    all_passed = True
    for cmd, description in test_commands:
        if not run_command(cmd, description):
            all_passed = False
    
    if all_passed:
        print("All tests passed!")
    else:
        print("Some tests failed!")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Security Monitoring Dashboard Deployment')
    parser.add_argument('--environment', '-e', choices=['dev', 'prod'], required=True,
                       help='Target environment')
    parser.add_argument('--server', '-s', help='Target server for production deployment')
    parser.add_argument('--username', '-u', help='SSH username for production deployment')
    parser.add_argument('--test', action='store_true', help='Run tests before deployment')
    
    args = parser.parse_args()
    
    if args.test:
        if not run_tests():
            print("Tests failed - aborting deployment")
            return 1
    
    if args.environment == 'dev':
        success = deploy_development()
    elif args.environment == 'prod':
        if not args.server or not args.username:
            print("Production deployment requires --server and --username")
            return 1
        success = deploy_production(args.server, args.username)
    
    return 0 if success else 1

if __name__ == "__main__":
    from datetime import datetime
    exit(main())