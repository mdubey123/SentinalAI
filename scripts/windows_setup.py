"""
Windows-specific setup script for SentinelAI v2
Handles Windows compatibility issues and provides alternatives
"""

import subprocess
import sys
import os
import platform
from pathlib import Path

def check_windows_requirements():
    """Check Windows-specific requirements"""
    print("Checking Windows environment...")
    
    # Check if running on Windows
    if platform.system() != "Windows":
        print("This script is for Windows only")
        return False
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        return False
    
    print(f"✓ Python {sys.version}")
    print(f"✓ Windows {platform.release()}")
    return True

def install_windows_dependencies():
    """Install Windows-compatible dependencies"""
    print("\nInstalling Windows-compatible packages...")
    
    # Use the Windows-specific requirements file
    if Path("requirements-windows.txt").exists():
        cmd = f"{sys.executable} -m pip install -r requirements-windows.txt"
        try:
            subprocess.run(cmd, shell=True, check=True)
            print("✓ Windows dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install dependencies: {e}")
            return False
    else:
        print("✗ requirements-windows.txt not found")
        return False

def create_windows_launcher():
    """Create Windows batch launcher"""
    launcher_content = """@echo off
title SentinelAI v2
echo Starting SentinelAI v2...
echo.

REM Check if virtual environment exists
if exist "env\\Scripts\\activate.bat" (
    echo Activating virtual environment...
    call env\\Scripts\\activate.bat
)

REM Start SentinelAI
echo Launching SentinelAI v2...
python -m streamlit run app.py --server.port 8501 --server.address localhost

echo.
echo SentinelAI v2 has stopped.
pause
"""
    
    try:
        with open("SentinelAI.bat", "w") as f:
            f.write(launcher_content)
        print("✓ Created SentinelAI.bat launcher")
        return True
    except Exception as e:
        print(f"✗ Failed to create launcher: {e}")
        return False

def main():
    """Main Windows setup function"""
    print("SentinelAI v2 - Windows Setup")
    print("=" * 30)
    
    if not check_windows_requirements():
        sys.exit(1)
    
    # Install dependencies
    if not install_windows_dependencies():
        print("\n⚠️  Dependency installation failed")
        print("Try running: pip install -r requirements-windows.txt")
    
    # Create launcher
    create_windows_launcher()
    
    print("\n" + "=" * 30)
    print("Windows setup complete!")
    print("\nTo run SentinelAI v2:")
    print("  1. Double-click SentinelAI.bat")
    print("  2. Or run: streamlit run app.py")
    print("\nNote: Some advanced features may be limited on Windows")

if __name__ == "__main__":
    main()
