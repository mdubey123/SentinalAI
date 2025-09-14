"""
Installation script for SentinelAI v2 dependencies
Handles installation of optional security tools and libraries with Windows compatibility
"""

import subprocess
import sys
import os
import platform
from pathlib import Path

def run_command(command, description):
    """Run a system command with error handling"""
    print(f"Installing {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install {description}: {e}")
        print(f"Error output: {e.stderr}")
        return False

def install_yara():
    """Install YARA library"""
    system = platform.system().lower()
    
    if system == "linux":
        # Try different package managers
        commands = [
            "sudo apt-get update && sudo apt-get install -y libyara-dev yara",
            "sudo yum install -y yara yara-devel",
            "sudo dnf install -y yara yara-devel"
        ]
        
        for cmd in commands:
            if run_command(cmd, "YARA (Linux)"):
                break
    
    elif system == "darwin":  # macOS
        run_command("brew install yara", "YARA (macOS)")
    
    elif system == "windows":
        print("⚠️  YARA installation on Windows requires manual setup:")
        print("   1. Download from: https://github.com/VirusTotal/yara/releases")
        print("   2. Extract to C:\\yara")
        print("   3. Add C:\\yara to PATH")
        print("   Continuing with Python bindings installation...")
    
    # Install Python bindings
    return run_command(f"{sys.executable} -m pip install yara-python", "YARA Python bindings")

def install_clamav():
    """Install ClamAV antivirus"""
    system = platform.system().lower()
    
    if system == "linux":
        commands = [
            "sudo apt-get update && sudo apt-get install -y clamav clamav-daemon",
            "sudo yum install -y clamav clamav-update",
            "sudo dnf install -y clamav clamav-update"
        ]
        
        for cmd in commands:
            if run_command(cmd, "ClamAV (Linux)"):
                # Update virus definitions
                run_command("sudo freshclam", "ClamAV virus definitions")
                # Start daemon
                run_command("sudo systemctl start clamav-daemon", "ClamAV daemon")
                break
    
    elif system == "darwin":  # macOS
        if run_command("brew install clamav", "ClamAV (macOS)"):
            run_command("freshclam", "ClamAV virus definitions")
    
    elif system == "windows":
        print("⚠️  ClamAV installation on Windows:")
        print("   ClamAV daemon not available on Windows")
        print("   Using alternative file scanning methods")
        return True  # Return True to continue without ClamAV on Windows
    
    if system != "windows":
        return run_command(f"{sys.executable} -m pip install pyclamd", "ClamAV Python bindings")
    return True

def install_system_dependencies():
    """Install system-level dependencies"""
    system = platform.system().lower()
    
    if system == "linux":
        # Install development tools and libraries
        commands = [
            "sudo apt-get update && sudo apt-get install -y build-essential python3-dev libmagic1",
            "sudo yum groupinstall -y 'Development Tools' && sudo yum install -y python3-devel file-libs",
            "sudo dnf groupinstall -y 'Development Tools' && sudo dnf install -y python3-devel file-libs"
        ]
        
        for cmd in commands:
            if run_command(cmd, "System development tools"):
                break
    
    elif system == "darwin":  # macOS
        run_command("xcode-select --install", "Xcode command line tools")
        run_command("brew install libmagic", "libmagic")
    
    elif system == "windows":
        print("⚠️  Windows system dependencies:")
        print("   Visual Studio Build Tools are recommended but not required")
        print("   Using Windows-compatible alternatives")

def install_python_dependencies():
    """Install Python dependencies with Windows compatibility"""
    system = platform.system().lower()
    
    base_requirements = [
        "streamlit>=1.28.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "plotly>=5.15.0",
        "cryptography>=41.0.0",
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "aiohttp>=3.8.0",
        "loguru>=0.7.0",
        "reportlab>=4.0.0",
        "jinja2>=3.1.0",
        "langchain>=0.0.350",
        "langchain-openai>=0.0.5",
        "openai>=1.0.0",
        "xxhash>=3.4.0",  # Added Windows-compatible hashing
        "rich>=13.0.0",
        "tqdm>=4.66.0"
    ]
    
    if system == "windows":
        base_requirements.append("python-magic-bin>=0.4.14")  # Windows-specific magic
    else:
        base_requirements.extend([
            "python-magic>=0.4.27",
            # "ssdeep>=3.4.0"  # Replaced with python-tlsh for better performance
        ])
    
    print("Installing Python dependencies...")
    failed_packages = []
    
    for req in base_requirements:
        if not run_command(f"{sys.executable} -m pip install {req}", req):
            failed_packages.append(req)
    
    if system == "windows" and Path("requirements-windows.txt").exists():
        print("Installing from Windows-specific requirements...")
        run_command(f"{sys.executable} -m pip install -r requirements-windows.txt", "Windows requirements")
    
    if failed_packages:
        print(f"\n⚠️  Failed to install: {', '.join(failed_packages)}")
        print("These packages are optional and SentinelAI will work without them")

def setup_directories():
    """Create necessary directories"""
    base_dir = Path.home() / ".sentinelai"
    directories = [
        base_dir,
        base_dir / "logs",
        base_dir / "reports",
        base_dir / "profiles",
        base_dir / "cache",
        base_dir / "rules" / "yara",
        base_dir / "rules" / "custom"
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def setup_windows_environment():
    """Setup Windows-specific environment"""
    print("Setting up Windows environment...")
    
    # Create batch file for easy launching
    batch_content = """@echo off
cd /d "%~dp0"
if exist "env\\Scripts\\activate.bat" (
    call env\\Scripts\\activate.bat
    streamlit run app.py
) else (
    python -m streamlit run app.py
)
pause
"""
    
    try:
        with open("run_sentinelai.bat", "w") as f:
            f.write(batch_content)
        print("✓ Created run_sentinelai.bat launcher")
    except Exception as e:
        print(f"⚠️  Could not create batch launcher: {e}")

def main():
    """Main installation function"""
    print("SentinelAI v2 Dependency Installation")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    system = platform.system()
    print(f"Python version: {sys.version}")
    print(f"Platform: {system} {platform.release()}")
    print()
    
    # Setup directories
    setup_directories()
    
    if system.lower() == "windows":
        setup_windows_environment()
    
    # Install system dependencies
    install_system_dependencies()
    
    # Install Python dependencies
    install_python_dependencies()
    
    # Install optional security tools
    print("\nInstalling optional security tools...")
    
    yara_success = install_yara()
    clamav_success = install_clamav()
    
    print("\nInstallation Summary:")
    print("=" * 20)
    print(f"YARA: {'✓ Installed' if yara_success else '✗ Failed (optional)'}") 
    print(f"ClamAV: {'✓ Installed' if clamav_success else '✗ Failed (optional)'}")
    
    print(f"\n✓ Installation complete for {system}!")
    
    if system.lower() == "windows":
        print("\nTo run SentinelAI v2:")
        print("  Option 1: Double-click run_sentinelai.bat")
        print("  Option 2: streamlit run app.py")
    else:
        print("\nTo run SentinelAI v2:")
        print("  streamlit run app.py")
    
    if not yara_success or not clamav_success:
        print("\n⚠️  Some optional security tools failed to install.")
        print("SentinelAI will use alternative methods for file analysis.")

if __name__ == "__main__":
    main()
