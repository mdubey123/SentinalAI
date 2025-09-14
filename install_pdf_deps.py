#!/usr/bin/env python3
"""
Install PDF generation dependencies for SentinelAI v2
"""

import subprocess
import sys
import os

def install_package(package):
    """Install a package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ Successfully installed {package}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package}: {e}")
        return False

def main():
    """Install PDF generation dependencies"""
    print("🔧 Installing PDF generation dependencies for SentinelAI v2...")
    
    # Required packages for PDF generation
    packages = [
        "reportlab",
        "fpdf2",
        "jinja2",
        "weasyprint"
    ]
    
    success_count = 0
    total_packages = len(packages)
    
    for package in packages:
        if install_package(package):
            success_count += 1
    
    print(f"\n📊 Installation Summary:")
    print(f"   Successfully installed: {success_count}/{total_packages} packages")
    
    if success_count == total_packages:
        print("✅ All PDF generation dependencies installed successfully!")
        print("📄 You can now generate PDF reports in SentinelAI v2")
    else:
        print("⚠️ Some packages failed to install. PDF generation may not work properly.")
        print("💡 Try running: pip install -r requirements.txt")

if __name__ == "__main__":
    main()
