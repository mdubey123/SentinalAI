#!/usr/bin/env python3
"""
Restart script for SentinelAI app with cache clearing
"""
import subprocess
import sys
import os
import time

def clear_cache():
    """Clear Python cache files"""
    print("🧹 Clearing Python cache...")
    for root, dirs, files in os.walk('.'):
        for dir_name in dirs:
            if dir_name == '__pycache__':
                cache_path = os.path.join(root, dir_name)
                try:
                    import shutil
                    shutil.rmtree(cache_path)
                    print(f"   Removed: {cache_path}")
                except Exception as e:
                    print(f"   Error removing {cache_path}: {e}")

def restart_app():
    """Restart the Streamlit app"""
    print("🚀 Starting SentinelAI with fresh CSS...")
    print("   The app will load with the updated UI improvements!")
    print("   If you still see old styles, please:")
    print("   1. Hard refresh your browser (Ctrl+F5 or Cmd+Shift+R)")
    print("   2. Clear browser cache")
    print("   3. Open in incognito/private mode")
    print()
    
    try:
        # Start the app
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", "8501", "--server.headless", "true"], check=True)
    except KeyboardInterrupt:
        print("\n👋 App stopped by user")
    except Exception as e:
        print(f"❌ Error starting app: {e}")

if __name__ == "__main__":
    print("🛡️ SentinelAI v2 - UI Refresh Tool")
    print("=" * 40)
    
    clear_cache()
    print()
    restart_app()
