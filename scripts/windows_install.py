"""
Comprehensive Windows installation script for SentinelAI v2
Handles all Windows compatibility issues and provides robust error handling
"""

import subprocess
import sys
import os
import platform
from pathlib import Path
import json

def check_python_version():
    """Check if Python version is compatible"""
    print("Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} - Compatible")
    return True

def check_virtual_environment():
    """Check if we're in a virtual environment"""
    print("\nChecking virtual environment...")
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment detected")
        return True
    else:
        print("⚠️  Warning: Not in a virtual environment")
        print("Consider creating one with: python -m venv env")
        return False

def upgrade_pip_and_setuptools():
    """Upgrade pip and setuptools to latest versions"""
    print("\nUpgrading pip and setuptools...")
    
    try:
        # Upgrade pip
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True, text=True)
        print("✅ pip upgraded successfully")
        
        # Upgrade setuptools
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "setuptools>=61"], 
                      check=True, capture_output=True, text=True)
        print("✅ setuptools upgraded successfully")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to upgrade pip/setuptools: {e}")
        return False

def install_windows_packages():
    """Install Windows-specific packages first"""
    print("\nInstalling Windows-specific packages...")
    
    windows_packages = [
        "python-magic-bin",  # Windows-compatible magic file detection
        "fuzzywuzzy[speedup]",  # Windows-compatible fuzzy string matching
        "xxhash",  # Fast hashing
        "win32-setctime",  # Windows file time utilities
    ]
    
    for package in windows_packages:
        try:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                          check=True, capture_output=True, text=True)
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    return True

def install_core_dependencies():
    """Install core dependencies from requirements file"""
    print("\nInstalling core dependencies...")
    
    try:
        # Use the Windows-specific requirements file
        if Path("requirements_windows.txt").exists():
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements_windows.txt"], 
                          check=True, capture_output=True, text=True)
            print("✅ Core dependencies installed successfully")
            return True
        else:
            print("❌ requirements_windows.txt not found")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install core dependencies: {e}")
        return False

def install_optional_dependencies():
    """Install optional dependencies that might fail"""
    print("\nInstalling optional dependencies...")
    
    optional_packages = [
        "yara-python",  # YARA rules engine
        "scapy",  # Network packet manipulation
        "weasyprint",  # PDF generation (might fail on Windows)
    ]
    
    for package in optional_packages:
        try:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                          check=True, capture_output=True, text=True)
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"⚠️  {package} failed to install (optional): {e}")
            # Continue with other packages

def verify_installation():
    """Verify that key packages are installed and working"""
    print("\nVerifying installation...")
    
    test_imports = [
        "streamlit",
        "pandas", 
        "numpy",
        "plotly",
        "langchain",
        "cryptography",
        "fuzzywuzzy",
        "requests",
        "python_magic",
    ]
    
    failed_imports = []
    
    for package in test_imports:
        try:
            __import__(package)
            print(f"✅ {package} - OK")
        except ImportError as e:
            print(f"❌ {package} - FAILED: {e}")
            failed_imports.append(package)
    
    if failed_imports:
        print(f"\n⚠️  {len(failed_imports)} packages failed to import:")
        for pkg in failed_imports:
            print(f"   - {pkg}")
        return False
    else:
        print("\n✅ All key packages verified successfully!")
        return True

def create_launcher_scripts():
    """Create Windows launcher scripts"""
    print("\nCreating launcher scripts...")
    
    # Create main launcher
    launcher_content = """@echo off
title SentinelAI v2 - Cybersecurity Analysis Platform
echo.
echo ========================================
echo    SentinelAI v2 - Starting...
echo ========================================
echo.

REM Check if virtual environment exists
if exist "env\\Scripts\\activate.bat" (
    echo Activating virtual environment...
    call env\\Scripts\\activate.bat
) else (
    echo Warning: Virtual environment not found
    echo Please run: python -m venv env
    echo Then run: env\\Scripts\\activate.bat
    echo.
)

REM Check if app.py exists
if not exist "app.py" (
    echo Error: app.py not found
    echo Please run this script from the SentinelAI v2 directory
    pause
    exit /b 1
)

REM Start SentinelAI
echo Launching SentinelAI v2...
echo.
echo The application will open in your default web browser
echo URL: http://localhost:8501
echo.
echo Press Ctrl+C to stop the application
echo.

python -m streamlit run app.py --server.port 8501 --server.address localhost

echo.
echo SentinelAI v2 has stopped.
pause
"""
    
    try:
        with open("SentinelAI.bat", "w", encoding="utf-8") as f:
            f.write(launcher_content)
        print("✅ Created SentinelAI.bat launcher")
    except Exception as e:
        print(f"❌ Failed to create launcher: {e}")
    
    # Create development launcher
    dev_launcher_content = """@echo off
title SentinelAI v2 - Development Mode
echo.
echo ========================================
echo    SentinelAI v2 - Development Mode
echo ========================================
echo.

REM Activate virtual environment
if exist "env\\Scripts\\activate.bat" (
    call env\\Scripts\\activate.bat
)

REM Start in development mode with auto-reload
python -m streamlit run app.py --server.port 8501 --server.address localhost --server.runOnSave true

pause
"""
    
    try:
        with open("SentinelAI_Dev.bat", "w", encoding="utf-8") as f:
            f.write(dev_launcher_content)
        print("✅ Created SentinelAI_Dev.bat launcher")
    except Exception as e:
        print(f"❌ Failed to create dev launcher: {e}")

def create_config_file():
    """Create a basic configuration file"""
    print("\nCreating configuration file...")
    
    config = {
        "app": {
            "name": "SentinelAI v2",
            "version": "2.0.0",
            "debug": False
        },
        "security": {
            "max_file_size_mb": 32,
            "scan_timeout_seconds": 300,
            "enable_audit_logging": True
        },
        "llm": {
            "default_provider": "OpenAI",
            "default_model": "gpt-4",
            "api_keys": {}
        },
        "virustotal": {
            "enabled": True,
            "api_key": "",
            "quota_limit": 500
        },
        "vapt": {
            "enabled": False,
            "default_scope": "Host Only",
            "max_ports": 1000
        }
    }
    
    try:
        with open("config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        print("✅ Created config.json")
    except Exception as e:
        print(f"❌ Failed to create config file: {e}")

def main():
    """Main installation function"""
    print("=" * 60)
    print("    SentinelAI v2 - Windows Installation Script")
    print("=" * 60)
    print()
    
    # Check system requirements
    if not check_python_version():
        sys.exit(1)
    
    if not check_virtual_environment():
        print("\n⚠️  Continuing without virtual environment...")
    
    # Upgrade pip and setuptools first
    if not upgrade_pip_and_setuptools():
        print("\n⚠️  Continuing with current pip/setuptools versions...")
    
    # Install Windows-specific packages
    if not install_windows_packages():
        print("\n❌ Failed to install Windows-specific packages")
        sys.exit(1)
    
    # Install core dependencies
    if not install_core_dependencies():
        print("\n❌ Failed to install core dependencies")
        sys.exit(1)
    
    # Install optional dependencies
    install_optional_dependencies()
    
    # Verify installation
    if not verify_installation():
        print("\n⚠️  Some packages failed to install, but core functionality should work")
    
    # Create launcher scripts
    create_launcher_scripts()
    
    # Create config file
    create_config_file()
    
    print("\n" + "=" * 60)
    print("    Installation Complete!")
    print("=" * 60)
    print()
    print("To run SentinelAI v2:")
    print("  1. Double-click SentinelAI.bat")
    print("  2. Or run: streamlit run app.py")
    print()
    print("For development:")
    print("  - Double-click SentinelAI_Dev.bat")
    print("  - Or run: streamlit run app.py --server.runOnSave true")
    print()
    print("Configuration:")
    print("  - Edit config.json to customize settings")
    print("  - Add API keys in the Streamlit interface")
    print()
    print("Troubleshooting:")
    print("  - If you get import errors, try: pip install --upgrade -r requirements_windows.txt")
    print("  - For YARA issues, install Visual Studio Build Tools")
    print("  - Check the logs in the logs/ directory")
    print()

if __name__ == "__main__":
    main()

