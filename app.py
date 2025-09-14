"""
SentinelAI v2 - Advanced Cybersecurity Analysis Platform
Dr. Alexandra Chen's Enterprise-Grade Security Assessment Tool

A comprehensive Streamlit application for malware detection, vulnerability assessment,
and AI-powered threat analysis with gamification and multi-LLM support.
"""

import streamlit as st
import os
import sys
import json
import asyncio
import hashlib
import logging
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Import custom modules
from core.config_manager import ConfigManager
from core.security_manager import SecurityManager
from agents.local_scan_agent import LocalScanAgent
from agents.virustotal_agent import VirusTotalAgent
from agents.vapt_agent import VAPTAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.report_agent import ReportAgent
from core.gamification import GamificationEngine
from utils.logger import setup_logger

# Configure Streamlit page
st.set_page_config(
    page_title="SentinelAI v2 - Cybersecurity Analysis Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize logging
logger = setup_logger()

def load_custom_css():
    """Load custom CSS directly"""
    custom_css = """
    <style>
    /* Professional Minimalistic Theme Colors */
    :root {
        --primary: #1e293b;       /* Sophisticated slate blue for primary actions */
        --primary-dark: #0f172a;  /* Deep slate for hover states */
        --primary-light: #475569; /* Lighter slate for secondary actions */
        --secondary: #64748b;     /* Cool gray for secondary elements */
        --accent: #3b82f6;        /* Professional blue accent - modern and trustworthy */
        --accent-dark: #2563eb;   /* Darker blue for hover states */
        --accent-light: #60a5fa;  /* Light blue for highlights */
        --success: #10b981;       /* Emerald green for success states */
        --success-light: #34d399; /* Light emerald for success highlights */
        --warning: #f59e0b;       /* Amber for warnings */
        --warning-light: #fbbf24; /* Light amber for warning highlights */
        --danger: #ef4444;        /* Red for errors */
        --danger-light: #f87171;  /* Light red for danger highlights */
        --background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); /* Subtle gradient background */
        --surface: rgba(255, 255, 255, 0.95); /* Semi-transparent white for glass effect */
        --surface-elevated: rgba(255, 255, 255, 0.98); /* More opaque for elevated surfaces */
        --surface-glass: rgba(255, 255, 255, 0.1); /* Glass effect for overlays */
        --text-primary: #0f172a;  /* Deep slate for primary text */
        --text-secondary: #64748b;/* Medium gray for secondary text */
        --text-muted: #94a3b8;    /* Light gray for muted text */
        --border: rgba(226, 232, 240, 0.6); /* Semi-transparent borders */
        --border-light: rgba(241, 245, 249, 0.8); /* Very light borders */
        --shadow: rgba(15, 23, 42, 0.1); /* Professional shadow */
        --shadow-hover: rgba(15, 23, 42, 0.15); /* Hover shadow */
        --shadow-glass: rgba(15, 23, 42, 0.05); /* Glass shadow */
        --gradient-primary: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        --gradient-accent: linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%);
        --gradient-success: linear-gradient(135deg, #10b981 0%, #34d399 100%);
        --gradient-warning: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
        --gradient-danger: linear-gradient(135deg, #ef4444 0%, #f87171 100%);
    }

    /* Base Styles */
    body, .stApp {
        background: var(--background) !important;
        color: var(--text-primary) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        min-height: 100vh !important;
    }

    /* Add subtle pattern overlay */
    .stApp::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image: 
            radial-gradient(circle at 20% 80%, rgba(59, 130, 246, 0.03) 0%, transparent 50%),
            radial-gradient(circle at 80% 20%, rgba(16, 185, 129, 0.03) 0%, transparent 50%),
            radial-gradient(circle at 40% 40%, rgba(245, 158, 11, 0.02) 0%, transparent 50%);
        pointer-events: none;
        z-index: -1;
    }

    /* Main content area */
    .main .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        max-width: 1200px !important;
    }

    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary);
        font-weight: 600;
        margin-bottom: 0.75rem;
    }

    /* Buttons */
    button, .stButton > button, .stButton > button:focus {
        background: var(--gradient-primary) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 0.875rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.875rem !important;
        letter-spacing: 0.025em !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 12px var(--shadow) !important;
        backdrop-filter: blur(10px) !important;
        position: relative !important;
        overflow: hidden !important;
    }

    .stButton > button::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
        transition: left 0.5s;
    }

    .stButton > button:hover::before {
        left: 100%;
    }

    .stButton > button:hover {
        background: var(--gradient-accent) !important;
        transform: translateY(-3px) !important;
        box-shadow: 0 8px 25px var(--shadow-hover) !important;
    }

    .stButton > button:active {
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px var(--shadow) !important;
    }

    /* Secondary Buttons */
    .stButton > button[kind="secondary"] {
        background: var(--surface) !important;
        color: var(--primary) !important;
        border: 1px solid var(--border) !important;
        backdrop-filter: blur(10px) !important;
    }

    .stButton > button[kind="secondary"]:hover {
        background: var(--surface-elevated) !important;
        border-color: var(--accent) !important;
        color: var(--accent) !important;
    }

    /* Success Buttons */
    .stButton > button[kind="primary"]:has([data-testid="stSuccess"]) {
        background: var(--gradient-success) !important;
    }

    /* Warning Buttons */
    .stButton > button[kind="primary"]:has([data-testid="stWarning"]) {
        background: var(--gradient-warning) !important;
    }

    /* Danger Buttons */
    .stButton > button[kind="primary"]:has([data-testid="stError"]) {
        background: var(--gradient-danger) !important;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: var(--surface) !important;
        border-right: 1px solid var(--border) !important;
        backdrop-filter: blur(20px) !important;
        box-shadow: 2px 0 20px var(--shadow-glass) !important;
    }
    
    section[data-testid="stSidebar"] > div:first-child {
        background: var(--surface) !important;
        backdrop-filter: blur(20px) !important;
    }

    /* Sidebar header */
    .stSidebar .stMarkdown h1 {
        background: var(--gradient-primary) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        font-size: 1.5rem !important;
        font-weight: 700 !important;
        margin-bottom: 0.5rem !important;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        border-bottom: 1px solid var(--border-light);
        margin-bottom: 2rem;
        background: var(--surface);
        border-radius: 16px 16px 0 0;
        padding: 0.5rem;
        backdrop-filter: blur(20px);
        box-shadow: 0 4px 20px var(--shadow-glass);
    }

    .stTabs [data-baseweb="tab"] {
        color: var(--text-secondary);
        padding: 1rem 2rem;
        margin-right: 0.5rem;
        border-radius: 12px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        font-weight: 500;
        font-size: 0.875rem;
        letter-spacing: 0.025em;
        position: relative;
        overflow: hidden;
    }

    .stTabs [data-baseweb="tab"]:hover {
        color: var(--text-primary);
        background: var(--surface-elevated);
        transform: translateY(-2px);
    }

    .stTabs [aria-selected="true"] {
        color: var(--accent);
        background: var(--surface);
        box-shadow: 0 4px 12px var(--shadow);
        font-weight: 600;
        transform: translateY(-2px);
    }

    .stTabs [aria-selected="true"]::before {
        content: '';
        position: absolute;
        bottom: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 60%;
        height: 3px;
        background: var(--gradient-accent);
        border-radius: 2px;
    }

    /* Input Fields */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div,
    input, textarea, select {
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
        padding: 0.75rem 1rem !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        background-color: var(--surface) !important;
        color: var(--text-primary) !important;
        font-size: 0.875rem !important;
        box-shadow: 0 1px 2px var(--shadow) !important;
    }

    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus,
    .stSelectbox > div > div > div:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.1) !important;
        outline: none !important;
    }

    .stTextInput > div > div > input:hover,
    .stTextArea > div > div > textarea:hover,
    .stSelectbox > div > div > div:hover {
        border-color: var(--accent) !important;
    }

    /* Cards and Containers */
    .stAlert, .stDataFrame, .stJson, .stMetric, .stExpander {
        border-radius: 16px !important;
        border: 1px solid var(--border-light) !important;
        box-shadow: 0 4px 20px var(--shadow-glass) !important;
        margin-bottom: 1.5rem !important;
        background: var(--surface) !important;
        backdrop-filter: blur(20px) !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        position: relative !important;
        overflow: hidden !important;
    }

    .stAlert::before, .stDataFrame::before, .stJson::before, .stMetric::before, .stExpander::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent, var(--accent-light), transparent);
        opacity: 0;
        transition: opacity 0.3s ease;
    }

    .stAlert:hover, .stDataFrame:hover, .stJson:hover, .stMetric:hover, .stExpander:hover {
        box-shadow: 0 8px 30px var(--shadow-hover) !important;
        transform: translateY(-4px) !important;
        border-color: var(--accent-light) !important;
    }

    .stAlert:hover::before, .stDataFrame:hover::before, .stJson:hover::before, .stMetric:hover::before, .stExpander:hover::before {
        opacity: 1;
    }

    /* Metrics Cards */
    .stMetric {
        padding: 2rem !important;
        text-align: center !important;
        background: var(--surface) !important;
        backdrop-filter: blur(20px) !important;
    }

    .stMetric > div {
        background: linear-gradient(135deg, var(--surface) 0%, var(--surface-elevated) 100%) !important;
        border-radius: 12px !important;
        padding: 1.5rem !important;
    }

    /* Expander styling */
    .stExpander {
        background: var(--surface) !important;
        backdrop-filter: blur(20px) !important;
    }

    .stExpander > div {
        background: transparent !important;
    }

    /* Status Indicators */
    .stAlert {
        border-left: 4px solid var(--accent) !important;
        padding: 1.5rem 2rem !important;
        font-weight: 500 !important;
        border-radius: 16px !important;
        backdrop-filter: blur(20px) !important;
    }

    .stAlert[data-testid="stNotification"] {
        border-left: 4px solid var(--success) !important;
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(16, 185, 129, 0.03) 100%) !important;
        box-shadow: 0 4px 20px rgba(16, 185, 129, 0.1) !important;
    }

    .stAlert[data-testid="stError"] {
        border-left: 4px solid var(--danger) !important;
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(239, 68, 68, 0.03) 100%) !important;
        box-shadow: 0 4px 20px rgba(239, 68, 68, 0.1) !important;
    }

    .stAlert[data-testid="stWarning"] {
        border-left: 4px solid var(--warning) !important;
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(245, 158, 11, 0.03) 100%) !important;
        box-shadow: 0 4px 20px rgba(245, 158, 11, 0.1) !important;
    }

    .stAlert[data-testid="stInfo"] {
        border-left: 4px solid var(--accent) !important;
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.08) 0%, rgba(59, 130, 246, 0.03) 100%) !important;
        box-shadow: 0 4px 20px rgba(59, 130, 246, 0.1) !important;
    }

    /* Progress Bars */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, var(--accent) 0%, var(--accent-dark) 100%) !important;
        border-radius: 4px !important;
    }

    /* File Uploader */
    .stFileUploader {
        border: 2px dashed var(--border) !important;
        border-radius: 16px !important;
        padding: 3rem 2rem !important;
        background: var(--surface) !important;
        backdrop-filter: blur(20px) !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        position: relative !important;
        overflow: hidden !important;
    }

    .stFileUploader::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(45deg, transparent 30%, rgba(59, 130, 246, 0.05) 50%, transparent 70%);
        opacity: 0;
        transition: opacity 0.3s ease;
    }

    .stFileUploader:hover {
        border-color: var(--accent) !important;
        background: var(--surface-elevated) !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 30px var(--shadow-hover) !important;
    }

    .stFileUploader:hover::before {
        opacity: 1;
    }

    /* Sidebar Enhancements */
    .stSidebar .stSelectbox, .stSidebar .stTextInput {
        margin-bottom: 1rem !important;
    }

    .stSidebar .stMarkdown h3 {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        margin-bottom: 0.75rem !important;
        font-size: 0.875rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
    }

    /* Custom Scrollbars */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }

    ::-webkit-scrollbar-track {
        background: var(--surface-elevated);
        border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb {
        background: var(--accent);
        border-radius: 4px;
        transition: background 0.3s ease;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: var(--accent-dark);
    }

    /* Header Styling */
    h1 {
        background: var(--gradient-primary) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        font-size: 2.5rem !important;
        font-weight: 800 !important;
        margin-bottom: 1rem !important;
        text-align: center !important;
    }

    h2 {
        color: var(--text-primary) !important;
        font-size: 1.875rem !important;
        font-weight: 700 !important;
        margin-bottom: 1.5rem !important;
        position: relative !important;
    }

    h2::after {
        content: '';
        position: absolute;
        bottom: -0.5rem;
        left: 0;
        width: 60px;
        height: 3px;
        background: var(--gradient-accent);
        border-radius: 2px;
    }

    /* Radio Buttons */
    .stRadio > div {
        background: var(--surface) !important;
        border-radius: 12px !important;
        padding: 1rem !important;
        backdrop-filter: blur(20px) !important;
        border: 1px solid var(--border-light) !important;
    }

    .stRadio > div:hover {
        border-color: var(--accent) !important;
        box-shadow: 0 4px 12px var(--shadow) !important;
    }

    /* Checkboxes */
    .stCheckbox > div {
        background: var(--surface) !important;
        border-radius: 8px !important;
        padding: 0.75rem !important;
        backdrop-filter: blur(20px) !important;
        border: 1px solid var(--border-light) !important;
    }

    /* Selectbox */
    .stSelectbox > div > div {
        background: var(--surface) !important;
        border-radius: 12px !important;
        backdrop-filter: blur(20px) !important;
    }

    /* Progress Bar */
    .stProgress > div > div > div > div {
        background-color: var(--primary);
    }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)

class SentinelAIApp:
    """Main SentinelAI v2 Application Class"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.security_manager = SecurityManager()
        self.gamification = GamificationEngine()
        
        # Initialize session state
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = {}
        if 'user_profile' not in st.session_state:
            st.session_state.user_profile = self.gamification.load_profile()
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
    
    def render_sidebar(self):
        """Render the main sidebar configuration"""
        st.sidebar.title("🛡️ SentinelAI v2")
        st.sidebar.markdown("*Precision Cybersecurity Analysis*")
        
        # LLM Configuration
        st.sidebar.subheader("🤖 AI Configuration")
        
        llm_providers = [
            "OpenAI", "Anthropic", "Google", "Cohere", 
            "Hugging Face", "Mistral", "Llama", "Local"
        ]
        
        selected_provider = st.sidebar.selectbox(
            "LLM Provider",
            llm_providers,
            index=0
        )
        
        # Model selection based on provider
        model_options = self.get_model_options(selected_provider)
        selected_model = st.sidebar.selectbox(
            "Model",
            model_options,
            index=0
        )
        
        # API Key input (encrypted storage)
        api_key = st.sidebar.text_input(
            f"{selected_provider} API Key",
            type="password",
            help="API key will be encrypted and stored locally"
        )
        
        if api_key:
            self.security_manager.store_encrypted_key(selected_provider.lower(), api_key)
        
        # VirusTotal Configuration
        st.sidebar.subheader("🔍 VirusTotal Integration")
        vt_enabled = st.sidebar.checkbox("Enable VirusTotal", value=True)
        
        if vt_enabled:
            vt_api_key = st.sidebar.text_input(
                "VirusTotal API Key",
                type="password",
                help="Optional: Leave empty for public API limits"
            )
            
            if vt_api_key:
                self.security_manager.store_encrypted_key("virustotal", vt_api_key)
        
        # Scan Configuration
        st.sidebar.subheader("⚙️ Scan Settings")
        
        scan_mode = st.sidebar.radio(
            "Scan Mode",
            ["Quick Scan", "Deep Scan", "Custom"]
        )
        
        # VAPT Settings
        vapt_enabled = st.sidebar.checkbox("Enable VAPT", value=False)
        
        if vapt_enabled:
            st.sidebar.warning("⚠️ VAPT scanning can be intrusive. Use responsibly.")
            vapt_scope = st.sidebar.radio(
                "VAPT Scope",
                ["Host Only", "Local Subnet"],
                help="Host Only is recommended for safety"
            )
        
        return {
            'llm_provider': selected_provider,
            'llm_model': selected_model,
            'vt_enabled': vt_enabled,
            'scan_mode': scan_mode,
            'vapt_enabled': vapt_enabled,
            'vapt_scope': vapt_scope if vapt_enabled else None
        }
    
    def get_model_options(self, provider: str) -> List[str]:
        """Get available models for the selected provider"""
        model_map = {
            "OpenAI": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
            "Anthropic": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
            "Google": ["gemini-pro", "gemini-pro-vision"],
            "Cohere": ["command", "command-light"],
            "Hugging Face": ["mistral-7b", "llama-2-7b", "code-llama"],
            "Mistral": ["mistral-large", "mistral-medium", "mistral-small"],
            "Llama": ["llama-2-70b", "llama-2-13b", "llama-2-7b"],
            "Local": ["local-model"]
        }
        return model_map.get(provider, ["default"])
    
    def render_main_tabs(self, config: Dict):
        """Render the main application tabs"""
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🔍 Scanner", "🎯 VAPT", "📊 Dashboard", "📋 Reports", "⚙️ Settings"
        ])
        
        with tab1:
            self.render_scanner_tab(config)
        
        with tab2:
            self.render_vapt_tab(config)
        
        with tab3:
            self.render_dashboard_tab()
        
        with tab4:
            self.render_reports_tab()
        
        with tab5:
            self.render_settings_tab()
    
    def render_scanner_tab(self, config: Dict):
        """Render the main scanner interface"""
        st.header("🔍 Malware Scanner")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Select Scan Target")
            
            scan_type = st.radio(
                "Scan Type",
                ["Folder Scan", "File Scan", "Hash Analysis"],
                horizontal=True
            )
            
            if scan_type == "Folder Scan":
                folder_path = st.text_input(
                    "Folder Path",
                    placeholder="/path/to/scan/folder",
                    help="Enter the full path to the folder you want to scan"
                )
                
                recursive = st.checkbox("Recursive Scan", value=True)
                exclude_system = st.checkbox("Exclude System Directories", value=True)
                
                if st.button("Start Folder Scan", type="primary"):
                    if folder_path and os.path.exists(folder_path):
                        self.run_folder_scan(folder_path, recursive, exclude_system, config)
                    else:
                        st.error("Please enter a valid folder path")
            
            elif scan_type == "File Scan":
                uploaded_files = st.file_uploader(
                    "Upload Files",
                    accept_multiple_files=True,
                    help="Upload files for malware analysis"
                )
                
                if uploaded_files and st.button("Scan Files", type="primary"):
                    self.run_file_scan(uploaded_files, config)
            
            elif scan_type == "Hash Analysis":
                hash_input = st.text_area(
                    "Enter File Hashes",
                    placeholder="Enter SHA256 hashes (one per line)",
                    help="Analyze known file hashes using VirusTotal"
                )
                
                if hash_input and st.button("Analyze Hashes", type="primary"):
                    hashes = [h.strip() for h in hash_input.split('\n') if h.strip()]
                    self.run_hash_analysis(hashes, config)
        
        with col2:
            self.render_scan_status()
    
    def render_vapt_tab(self, config: Dict):
        """Render VAPT (Vulnerability Assessment & Penetration Testing) interface"""
        st.header("🎯 Vulnerability Assessment & Penetration Testing")
        
        if not config.get('vapt_enabled'):
            st.info("VAPT is disabled. Enable it in the sidebar to access these features.")
            return
        
        st.warning("⚠️ **WARNING**: VAPT tools can be intrusive and should only be used on systems you own or have explicit permission to test.")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            vapt_type = st.selectbox(
                "Assessment Type",
                ["Port Scan", "Service Fingerprinting", "Vulnerability Scan", "Full Assessment"]
            )
            
            if config['vapt_scope'] == "Host Only":
                target = st.text_input(
                    "Target Host",
                    value="127.0.0.1",
                    help="IP address or hostname to scan"
                )
            else:
                target = st.text_input(
                    "Target Range",
                    placeholder="192.168.1.0/24",
                    help="IP range or CIDR notation"
                )
            
            port_range = st.text_input(
                "Port Range",
                value="1-1000",
                help="Port range to scan (e.g., 1-1000, 80,443,8080)"
            )
            
            if st.button("Start VAPT Assessment", type="primary"):
                if target:
                    self.run_vapt_assessment(target, port_range, vapt_type, config)
                else:
                    st.error("Please specify a target")
        
        with col2:
            self.render_vapt_status()
    
    def render_dashboard_tab(self):
        """Render the main dashboard with analytics and gamification"""
        st.header("📊 Security Dashboard")
        
        # User Profile and Gamification
        col1, col2, col3 = st.columns(3)
        
        with col1:
            profile = st.session_state.user_profile
            st.metric(
                "Security Score",
                f"{profile.get('security_score', 0)}/100",
                delta=profile.get('score_change', 0)
            )
        
        with col2:
            st.metric(
                "Level",
                profile.get('level', 1),
                delta=profile.get('level_change', 0)
            )
        
        with col3:
            st.metric(
                "Scans Completed",
                profile.get('scans_completed', 0),
                delta=1 if st.session_state.scan_results else 0
            )
        
        # Badges and Achievements
        st.subheader("🏆 Achievements")
        badges = profile.get('badges', [])
        if badges:
            cols = st.columns(min(len(badges), 4))
            for i, badge in enumerate(badges[:4]):
                with cols[i]:
                    st.info(f"🏅 {badge}")
        else:
            st.info("Complete your first scan to earn badges!")
        
        # Recent Scan Results
        if st.session_state.scan_results:
            st.subheader("📈 Latest Scan Analysis")
            self.render_scan_results_dashboard()
        
        # Historical Trends
        if st.session_state.scan_history:
            st.subheader("📊 Security Trends")
            self.render_trend_charts()
    
    def render_reports_tab(self):
        """Render the reports and export interface"""
        st.header("📋 Reports & Export")
        
        if not st.session_state.scan_results:
            st.info("No scan results available. Complete a scan to generate reports.")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📄 Executive Report")
            st.write("Generate a non-technical, executive-friendly PDF report")
            
            if st.button("Generate PDF Report", type="primary"):
                self.generate_pdf_report()
        
        with col2:
            st.subheader("🔧 Technical Export")
            st.write("Export detailed JSON data for SIEM integration")
            
            if st.button("Export JSON", type="secondary"):
                self.export_json_report()
        
        # Report Preview
        st.subheader("📋 Report Preview")
        self.render_report_preview()
    
    def render_settings_tab(self):
        """Render application settings and configuration"""
        st.header("⚙️ Settings")
        
        # Security Settings
        st.subheader("🔒 Security Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.checkbox("Enable Audit Logging", value=True)
            st.checkbox("Prompt Injection Protection", value=True)
            st.checkbox("Auto-save Scan Results", value=True)
        
        with col2:
            st.number_input("API Rate Limit (requests/min)", value=60, min_value=1)
            st.number_input("Max File Size (MB)", value=32, min_value=1)
            st.selectbox("Log Level", ["INFO", "DEBUG", "WARNING", "ERROR"])
        
        # Data Management
        st.subheader("💾 Data Management")
        
        if st.button("Clear Scan History"):
            st.session_state.scan_history = []
            st.success("Scan history cleared")
        
        if st.button("Reset User Profile"):
            st.session_state.user_profile = self.gamification.create_new_profile()
            st.success("User profile reset")
        
        if st.button("Export All Data"):
            self.export_all_data()
    
    def render_scan_status(self):
        """Render current scan status and progress"""
        st.subheader("📊 Scan Status")
        
        if 'scan_progress' in st.session_state:
            progress = st.session_state.scan_progress
            st.progress(progress.get('percentage', 0) / 100)
            st.write(f"Status: {progress.get('status', 'Ready')}")
            st.write(f"Files Processed: {progress.get('files_processed', 0)}")
            
            if progress.get('threats_found', 0) > 0:
                st.error(f"⚠️ {progress['threats_found']} threats detected!")
        else:
            st.info("Ready to scan")
    
    def render_vapt_status(self):
        """Render VAPT assessment status"""
        st.subheader("🎯 VAPT Status")
        
        if 'vapt_progress' in st.session_state:
            progress = st.session_state.vapt_progress
            st.progress(progress.get('percentage', 0) / 100)
            st.write(f"Status: {progress.get('status', 'Ready')}")
            st.write(f"Ports Scanned: {progress.get('ports_scanned', 0)}")
            
            if progress.get('vulnerabilities', 0) > 0:
                st.warning(f"🔍 {progress['vulnerabilities']} vulnerabilities found")
        else:
            st.info("Ready for assessment")
    
    def render_scan_results_dashboard(self):
        """Render detailed scan results with visualizations"""
        results = st.session_state.scan_results
        
        # Threat Distribution
        if 'threats' in results:
            threat_data = results['threats']
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Severity Distribution
                severity_counts = {}
                for threat in threat_data:
                    severity = threat.get('severity', 'Unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                if severity_counts:
                    fig = px.pie(
                        values=list(severity_counts.values()),
                        names=list(severity_counts.keys()),
                        title="Threat Severity Distribution"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Threat Types
                type_counts = {}
                for threat in threat_data:
                    threat_type = threat.get('type', 'Unknown')
                    type_counts[threat_type] = type_counts.get(threat_type, 0) + 1
                
                if type_counts:
                    fig = px.bar(
                        x=list(type_counts.keys()),
                        y=list(type_counts.values()),
                        title="Threat Types Detected"
                    )
                    st.plotly_chart(fig, use_container_width=True)
        
        # File Analysis Details
        if 'local_scan' in results and results['local_scan'].get('files'):
            st.subheader("📁 File Analysis Details")
            
            files = results['local_scan']['files']
            for i, file_info in enumerate(files[:10]):  # Show first 10 files
                with st.expander(f"📄 {file_info.get('file_name', f'File {i+1}')} - {'✅ Clean' if file_info.get('is_clean', True) else '⚠️ Threats Detected'}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**File Path:** {file_info.get('file_path', 'Unknown')}")
                        st.write(f"**File Size:** {file_info.get('file_size', 0):,} bytes")
                        st.write(f"**MIME Type:** {file_info.get('mime_type', 'Unknown')}")
                        st.write(f"**Extension:** {file_info.get('file_extension', 'None')}")
                        
                        # Display hashes
                        hashes = file_info.get('hashes', {})
                        if hashes:
                            st.write("**File Hashes:**")
                            if hashes.get('md5'):
                                st.code(f"MD5: {hashes['md5']}")
                            if hashes.get('sha1'):
                                st.code(f"SHA1: {hashes['sha1']}")
                            if hashes.get('sha256'):
                                st.code(f"SHA256: {hashes['sha256']}")
                            if hashes.get('fuzzy'):
                                st.code(f"Fuzzy: {hashes['fuzzy']}")
                                st.caption("Fuzzy hash for similarity detection")
                    
                    with col2:
                        st.write(f"**Created:** {file_info.get('created_time', 'Unknown')}")
                        st.write(f"**Modified:** {file_info.get('modified_time', 'Unknown')}")
                        st.write(f"**Threat Count:** {file_info.get('threat_count', 0)}")
                    
                    # Display threats for this file
                    file_threats = [t for t in threat_data if t.get('file_path') == file_info.get('file_path')]
                    if file_threats:
                        st.write("**Threats Detected:**")
                        for threat in file_threats:
                            severity_color = {
                                'critical': '🔴',
                                'high': '🟠',
                                'medium': '🟡',
                                'low': '🟢'
                            }.get(threat.get('severity', 'unknown'), '⚪')
                            
                            st.write(f"{severity_color} **{threat.get('threat_name', 'Unknown Threat')}**")
                            st.write(f"   - Engine: {threat.get('engine', 'Unknown')}")
                            st.write(f"   - Confidence: {threat.get('confidence', 0)}%")
                            st.write(f"   - Description: {threat.get('description', 'No description')}")
            
            if len(files) > 10:
                st.info(f"Showing first 10 files out of {len(files)} total files scanned.")
    
    def render_trend_charts(self):
        """Render historical trend analysis"""
        history = st.session_state.scan_history
        
        if len(history) < 2:
            st.info("Need at least 2 scans to show trends")
            return
        
        # Security Score Trend
        dates = [scan['date'] for scan in history]
        scores = [scan.get('security_score', 0) for scan in history]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=dates,
            y=scores,
            mode='lines+markers',
            name='Security Score',
            line=dict(color='#1f77b4', width=3)
        ))
        
        fig.update_layout(
            title="Security Score Trend",
            xaxis_title="Date",
            yaxis_title="Security Score",
            yaxis=dict(range=[0, 100])
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_report_preview(self):
        """Render a preview of the current report"""
        results = st.session_state.scan_results
        
        if not results:
            return
        
        st.markdown("### Executive Summary")
        
        # Generate AI-powered summary
        summary = self.generate_executive_summary(results)
        st.write(summary)
        
        # Key Findings
        st.markdown("### Key Findings")
        
        threats = results.get('threats', [])
        if threats:
            for i, threat in enumerate(threats[:5]):  # Show top 5
                severity_color = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(threat.get('severity', 'Unknown'), '⚪')
                
                st.write(f"{severity_color} **{threat.get('name', 'Unknown Threat')}**")
                st.write(f"   - File: {threat.get('file', 'N/A')}")
                st.write(f"   - Type: {threat.get('type', 'N/A')}")
                st.write(f"   - Confidence: {threat.get('confidence', 0)}%")
        else:
            st.success("✅ No threats detected in the latest scan")
    
    def run_folder_scan(self, folder_path: str, recursive: bool, exclude_system: bool, config: Dict):
        """Execute complete end-to-end workflow for folder scanning"""
        try:
            # Step 1: Config Manager Agent - Initialize LLM and secure API keys
            st.session_state.scan_progress = {
                'status': 'Config Manager: Initializing LLM and securing API keys...',
                'percentage': 5,
                'files_processed': 0,
                'threats_found': 0
            }
            
            progress_bar = st.progress(0.05)
            status_text = st.empty()
            status_text.text("🔧 Config Manager: Securing configuration...")
            
            # Initialize and configure LLM
            llm_config = self.config_manager.initialize_llm(
                config['llm_provider'], 
                config['llm_model']
            )
            
            # Secure API keys
            if config['vt_enabled']:
                vt_key = self.security_manager.get_decrypted_key('virustotal')
                if not vt_key:
                    st.warning("VirusTotal API key not found. Proceeding with local-only analysis.")
            
            # Step 2: Local Scan Agent - Hash files and run malware detection
            st.session_state.scan_progress.update({
                'status': 'Local Scan Agent: Hashing files and detecting malware...',
                'percentage': 15
            })
            progress_bar.progress(0.15)
            status_text.text("🔍 Local Scan Agent: Performing SHA256 + fuzzy hashing...")
            
            local_agent = LocalScanAgent()
            local_results = local_agent.scan_folder(
                folder_path, recursive, exclude_system
            )
            
            st.session_state.scan_progress.update({
                'status': 'Local Scan Agent: ClamAV + YARA scanning complete',
                'percentage': 30,
                'files_processed': len(local_results.get('files', []))
            })
            progress_bar.progress(0.30)
            status_text.text("🦠 Local Scan Agent: ClamAV + YARA analysis complete")
            
            # Step 3: VirusTotal Agent (Optional) - Hash lookup and file upload
            vt_results = {}
            if config['vt_enabled'] and local_results.get('hashes'):
                st.session_state.scan_progress.update({
                    'status': 'VirusTotal Agent: Checking file hashes...',
                    'percentage': 40
                })
                progress_bar.progress(0.40)
                status_text.text("🌐 VirusTotal Agent: Hash lookup in progress...")
                
                vt_agent = VirusTotalAgent()
                
                # First check hashes (quota optimization)
                hash_results = vt_agent.check_hashes(local_results['hashes'])
                
                # Upload files <32MB if hash not found
                upload_results = {}
                if hash_results.get('unknown_hashes'):
                    status_text.text("📤 VirusTotal Agent: Uploading unknown files...")
                    upload_results = vt_agent.upload_unknown_files(
                        local_results['files'], 
                        hash_results['unknown_hashes']
                    )
                
                vt_results = {**hash_results, **upload_results}
                
                # Handle quota exceeded with fallback
                if vt_results.get('quota_exceeded'):
                    st.warning("⚠️ VirusTotal quota exceeded. Falling back to local-only results.")
                    status_text.text("⚠️ VirusTotal Agent: Quota exceeded, using local results")
                else:
                    status_text.text("✅ VirusTotal Agent: Analysis complete")
                
                st.session_state.scan_progress.update({
                    'status': 'VirusTotal Agent: Analysis complete',
                    'percentage': 50
                })
                progress_bar.progress(0.50)
            
            # Step 4: VAPT Agent (if enabled)
            vapt_results = {}
            if config.get('vapt_enabled'):
                st.session_state.scan_progress.update({
                    'status': 'VAPT Agent: Host scanning and service fingerprinting...',
                    'percentage': 60
                })
                progress_bar.progress(0.60)
                status_text.text("🎯 VAPT Agent: Port scanning and CVE lookup...")
                
                vapt_agent = VAPTAgent()
                
                # Host-only scan (default) or subnet scan with warnings
                if config.get('vapt_scope') == 'Local Subnet':
                    st.warning("🚨 Performing subnet scan - ensure you have authorization!")
                
                vapt_results = vapt_agent.assess_host('127.0.0.1')  # Default to localhost
                
                st.session_state.scan_progress.update({
                    'status': 'VAPT Agent: Vulnerability assessment complete',
                    'percentage': 70
                })
                progress_bar.progress(0.70)
                status_text.text("🔍 VAPT Agent: Configuration weakness detection complete")
            
            # Step 5: Threat Intelligence & AI Reasoning Agent
            st.session_state.scan_progress.update({
                'status': 'AI Reasoning Agent: Aggregating and analyzing results...',
                'percentage': 80
            })
            progress_bar.progress(0.80)
            status_text.text("🤖 AI Reasoning Agent: Threat classification and severity scoring...")
            
            # Aggregate all results
            combined_results = {
                'local': local_results,
                'virustotal': vt_results,
                'vapt': vapt_results,
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'scan_path': folder_path,
                    'config': config,
                    'workflow_version': '2.1'
                }
            }
            
            # AI Analysis with comprehensive reasoning
            ti_agent = ThreatIntelligenceAgent(config['llm_provider'], config['llm_model'])
            ai_analysis = ti_agent.analyze_threats(combined_results)
            
            # Generate dual storytelling
            narrative_story = ti_agent.generate_attacker_narrative(ai_analysis)
            analytical_breakdown = ti_agent.generate_analytical_breakdown(ai_analysis)
            
            # Map to security frameworks
            framework_mapping = ti_agent.map_to_frameworks(ai_analysis)
            
            st.session_state.scan_progress.update({
                'status': 'AI Reasoning Agent: CVSS, MITRE ATT&CK, NIST mapping complete',
                'percentage': 90
            })
            progress_bar.progress(0.90)
            status_text.text("📊 AI Reasoning Agent: Security framework mapping complete")
            
            # Step 6: Report Agent - Dashboard and export generation
            st.session_state.scan_progress.update({
                'status': 'Report Agent: Generating dashboard and reports...',
                'percentage': 95
            })
            progress_bar.progress(0.95)
            status_text.text("📋 Report Agent: Interactive dashboard generation...")
            
            # Finalize comprehensive results
            final_results = {
                **combined_results,
                'ai_analysis': ai_analysis,
                'storytelling': {
                    'narrative': narrative_story,
                    'analytical': analytical_breakdown
                },
                'framework_mapping': framework_mapping,
                'security_score': ai_analysis.get('security_score', 0),
                'remediation_guidance': ai_analysis.get('remediation', [])
            }
            
            # Step 7: User Dashboard & Notifications - Update gamification
            st.session_state.scan_results = final_results
            st.session_state.scan_history.append({
                'date': datetime.now().isoformat(),
                'type': 'folder_scan',
                'path': folder_path,
                'security_score': final_results['security_score'],
                'threats_found': len(ai_analysis.get('threats', [])),
                'workflow_complete': True
            })
            
            # Update gamification and achievements
            self.gamification.update_profile_after_scan(
                st.session_state.user_profile,
                final_results
            )
            
            # Check for new badges and achievements
            new_badges = self.gamification.check_achievements(
                st.session_state.user_profile,
                final_results
            )
            
            if new_badges:
                for badge in new_badges:
                    st.balloons()
                    st.success(f"🏆 Achievement Unlocked: {badge}")
            
            st.session_state.scan_progress.update({
                'status': 'Workflow Complete: All agents executed successfully',
                'percentage': 100,
                'threats_found': len(ai_analysis.get('threats', []))
            })
            progress_bar.progress(1.0)
            status_text.text("✅ Complete End-to-End Workflow Executed Successfully!")
            
            # Display workflow summary
            self.display_workflow_summary(final_results)
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {str(e)}")
            st.error(f"❌ Workflow execution failed: {str(e)}")
            
            # Log the failure for audit trail
            self.security_manager.log_security_event(
                'workflow_failure',
                {'error': str(e), 'scan_path': folder_path}
            )
    
    def run_file_scan(self, uploaded_files, config: Dict):
        """Execute file scan on uploaded files"""
        try:
            if not uploaded_files:
                st.error("No files uploaded for scanning")
                return
            
            # Step 1: Config Manager Agent - Initialize LLM and secure API keys
            st.session_state.scan_progress = {
                'status': 'Config Manager: Initializing LLM and securing API keys...',
                'percentage': 5,
                'files_processed': 0,
                'threats_found': 0
            }
            
            progress_bar = st.progress(0.05)
            status_text = st.empty()
            status_text.text("🔧 Config Manager: Securing configuration...")
            
            # Initialize and configure LLM
            llm_config = self.config_manager.initialize_llm(
                config['llm_provider'], 
                config['llm_model']
            )
            
            # Secure API keys
            if config['vt_enabled']:
                vt_key = self.security_manager.get_decrypted_key('virustotal')
                if not vt_key:
                    st.warning("VirusTotal API key not found. Proceeding with local-only analysis.")
            
            # Step 2: Save uploaded files temporarily and scan them
            st.session_state.scan_progress.update({
                'status': 'Local Scan Agent: Processing uploaded files...',
                'percentage': 15
            })
            progress_bar.progress(0.15)
            status_text.text("📁 Processing uploaded files...")
            
            # Create temporary directory for uploaded files
            import tempfile
            import shutil
            temp_dir = tempfile.mkdtemp(prefix="sentinelai_scan_")
            
            try:
                # Save uploaded files to temporary directory
                file_paths = []
                for uploaded_file in uploaded_files:
                    file_path = os.path.join(temp_dir, uploaded_file.name)
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    file_paths.append(file_path)
                
                # Step 3: Local Scan Agent - Scan the files
                st.session_state.scan_progress.update({
                    'status': 'Local Scan Agent: Scanning files with multiple engines...',
                    'percentage': 25
                })
                progress_bar.progress(0.25)
                status_text.text("🔍 Local Scan Agent: Performing SHA256 + fuzzy hashing...")
                
                local_agent = LocalScanAgent()
                
                # Scan each file individually
                all_results = {
                    'files': [],
                    'threats': [],
                    'hashes': {},
                    'errors': []
                }
                
                for i, file_path in enumerate(file_paths):
                    # Update progress
                    progress = 25 + (i * 20 / len(file_paths))
                    st.session_state.scan_progress.update({
                        'status': f'Scanning file {i+1}/{len(file_paths)}: {os.path.basename(file_path)}',
                        'percentage': progress
                    })
                    progress_bar.progress(progress / 100)
                    status_text.text(f"🔍 Scanning: {os.path.basename(file_path)}")
                    
                    # Scan single file
                    file_result = local_agent._scan_file_sync(file_path)
                    if file_result:
                        all_results['files'].append(file_result)
                        all_results['hashes'][file_path] = file_result.get('hashes', {})
                        if file_result.get('threats'):
                            all_results['threats'].extend(file_result['threats'])
                
                st.session_state.scan_progress.update({
                    'status': 'Local Scan Agent: ClamAV + YARA scanning complete',
                    'percentage': 45,
                    'files_processed': len(all_results.get('files', [])),
                    'threats_found': len(all_results.get('threats', []))
                })
                progress_bar.progress(0.45)
                status_text.text("🦠 Local Scan Agent: ClamAV + YARA analysis complete")
                
                # Step 4: VirusTotal Agent (Optional) - Hash lookup
                vt_results = {}
                if config['vt_enabled'] and vt_key:
                    st.session_state.scan_progress.update({
                        'status': 'VirusTotal Agent: Checking file hashes...',
                        'percentage': 60
                    })
                    progress_bar.progress(0.60)
                    status_text.text("🌐 VirusTotal Agent: Checking file hashes...")
                    
                    vt_agent = VirusTotalAgent()
                    for file_path in file_paths:
                        file_info = next((f for f in all_results['files'] if f['file_path'] == file_path), None)
                        if file_info and 'hashes' in file_info:
                            sha256_hash = file_info['hashes'].get('sha256')
                            if sha256_hash:
                                vt_result = vt_agent.get_file_report(sha256_hash)
                                if vt_result:
                                    vt_results[file_path] = vt_result
                
                # Step 5: AI Analysis Agent - Analyze results
                st.session_state.scan_progress.update({
                    'status': 'AI Analysis Agent: Analyzing scan results...',
                    'percentage': 75
                })
                progress_bar.progress(0.75)
                status_text.text("🤖 AI Analysis Agent: Analyzing scan results...")
                
                ai_agent = ThreatIntelligenceAgent(
                    config['llm_provider'], 
                    config['llm_model']
                )
                
                # Prepare scan results for AI analysis
                scan_results = {
                    'local_scan': all_results,
                    'virustotal': vt_results,
                    'config': config
                }
                
                ai_analysis = ai_agent.analyze_threats(scan_results)
                
                # Step 6: Finalize comprehensive results
                st.session_state.scan_progress.update({
                    'status': 'Finalizing comprehensive results...',
                    'percentage': 90
                })
                progress_bar.progress(0.90)
                status_text.text("📊 Finalizing comprehensive results...")
                
                # Create final results structure
                final_results = {
                    'local_scan': all_results,
                    'virustotal': vt_results,
                    'ai_analysis': ai_analysis,
                    'threats': ai_analysis.get('threats', []),  # Add threats at top level for dashboard
                    'security_score': ai_analysis.get('security_score', 0),  # Add security score for dashboard
                    'metadata': {
                        'scan_time': datetime.now().isoformat(),
                        'scan_type': 'file_scan',
                        'file_count': len(uploaded_files),
                        'config': config,
                        'workflow_version': '2.1'
                    }
                }
                
                # Final progress update
                st.session_state.scan_progress.update({
                    'status': 'Complete End-to-End Workflow Executed Successfully!',
                    'percentage': 100,
                    'files_processed': len(all_results.get('files', [])),
                    'threats_found': len(ai_analysis.get('threats', []))
                })
                progress_bar.progress(1.0)
                status_text.text("✅ Complete End-to-End Workflow Executed Successfully!")
                
                # Update session state for dashboard
                st.session_state.scan_results = final_results
                st.session_state.scan_history.append({
                    'date': datetime.now().isoformat(),
                    'type': 'file_scan',
                    'file_count': len(uploaded_files),
                    'security_score': ai_analysis.get('security_score', 0),
                    'threats_found': len(ai_analysis.get('threats', [])),
                    'workflow_complete': True
                })
                
                # Update gamification and achievements
                self.gamification.update_profile_after_scan(
                    st.session_state.user_profile,
                    final_results
                )
                
                # Check for new badges and achievements
                old_achievements = set(st.session_state.user_profile.get('achievements', []))
                old_badges = set(st.session_state.user_profile.get('badges', []))
                
                self.gamification._check_achievements(st.session_state.user_profile)
                self.gamification._check_badges(st.session_state.user_profile)
                
                # Check for new achievements
                new_achievements = set(st.session_state.user_profile.get('achievements', [])) - old_achievements
                new_badges = set(st.session_state.user_profile.get('badges', [])) - old_badges
                
                if new_achievements:
                    for achievement_id in new_achievements:
                        achievement = self.gamification.achievements.get(achievement_id, {})
                        st.balloons()
                        st.success(f"🏆 Achievement Unlocked: {achievement.get('name', achievement_id)}")
                
                if new_badges:
                    for badge_id in new_badges:
                        badge = self.gamification.badge_definitions.get(badge_id, {})
                        st.balloons()
                        st.success(f"🏅 Badge Earned: {badge.get('name', badge_id)}")
                
                # Display results
                self.display_file_scan_results(final_results, uploaded_files)
                
            finally:
                # Clean up temporary files
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e}")
            
        except Exception as e:
            logger.error(f"File scan execution failed: {str(e)}")
            st.error(f"❌ File scan execution failed: {str(e)}")
            
            # Log the failure for audit trail
            self.security_manager.log_security_event(
                'file_scan_failure',
                {'error': str(e), 'file_count': len(uploaded_files) if uploaded_files else 0}
            )
    
    def display_file_scan_results(self, results: Dict, uploaded_files):
        """Display file scan results in a user-friendly format"""
        try:
            st.header("📊 File Scan Results")
            
            # Summary statistics
            local_scan = results.get('local_scan', {})
            ai_analysis = results.get('ai_analysis', {})
            threats = ai_analysis.get('threats', [])
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Files Scanned", len(local_scan.get('files', [])))
            
            with col2:
                st.metric("Threats Detected", len(threats))
            
            with col3:
                clean_files = len([f for f in local_scan.get('files', []) if f.get('is_clean', True)])
                st.metric("Clean Files", clean_files)
            
            with col4:
                infected_files = len([f for f in local_scan.get('files', []) if not f.get('is_clean', True)])
                st.metric("Infected Files", infected_files)
            
            # File-by-file results
            st.subheader("📁 File Analysis Details")
            
            for i, uploaded_file in enumerate(uploaded_files):
                file_info = local_scan.get('files', [])[i] if i < len(local_scan.get('files', [])) else None
                
                if file_info:
                    with st.expander(f"📄 {uploaded_file.name} - {'✅ Clean' if file_info.get('is_clean', True) else '⚠️ Threats Detected'}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**File Size:** {file_info.get('file_size', 0):,} bytes")
                            st.write(f"**MIME Type:** {file_info.get('mime_type', 'Unknown')}")
                            st.write(f"**Extension:** {file_info.get('file_extension', 'None')}")
                            
                            # Display hashes
                            hashes = file_info.get('hashes', {})
                            if hashes:
                                st.write("**File Hashes:**")
                                if hashes.get('md5'):
                                    st.code(f"MD5: {hashes['md5']}")
                                if hashes.get('sha1'):
                                    st.code(f"SHA1: {hashes['sha1']}")
                                if hashes.get('sha256'):
                                    st.code(f"SHA256: {hashes['sha256']}")
                                if hashes.get('fuzzy'):
                                    st.code(f"Fuzzy: {hashes['fuzzy']}")
                                    st.caption("Fuzzy hash for similarity detection")
                        
                        with col2:
                            st.write(f"**Created:** {file_info.get('created_time', 'Unknown')}")
                            st.write(f"**Modified:** {file_info.get('modified_time', 'Unknown')}")
                            st.write(f"**Threat Count:** {file_info.get('threat_count', 0)}")
                        
                        # Display threats for this file
                        file_threats = [t for t in threats if t.get('file_path') == file_info.get('file_path')]
                        if file_threats:
                            st.write("**🚨 Threats Detected:**")
                            for threat in file_threats:
                                severity_color = {
                                    'critical': '🔴',
                                    'high': '🟠', 
                                    'medium': '🟡',
                                    'low': '🟢'
                                }.get(threat.get('severity', 'medium'), '🟡')
                                
                                st.write(f"{severity_color} **{threat.get('threat_name', 'Unknown Threat')}**")
                                st.write(f"   Engine: {threat.get('engine', 'Unknown')}")
                                st.write(f"   Severity: {threat.get('severity', 'Unknown')}")
                                st.write(f"   Confidence: {threat.get('confidence', 0)}%")
                                st.write(f"   Description: {threat.get('description', 'No description')}")
                                st.write("---")
            
            # Overall threat summary
            if threats:
                st.subheader("🚨 Threat Summary")
                
                # Group threats by severity
                threat_by_severity = {}
                for threat in threats:
                    severity = threat.get('severity', 'unknown')
                    if severity not in threat_by_severity:
                        threat_by_severity[severity] = []
                    threat_by_severity[severity].append(threat)
                
                for severity in ['critical', 'high', 'medium', 'low']:
                    if severity in threat_by_severity:
                        st.write(f"**{severity.upper()} Severity Threats ({len(threat_by_severity[severity])}):**")
                        for threat in threat_by_severity[severity]:
                            st.write(f"• {threat.get('threat_name', 'Unknown')} - {threat.get('description', 'No description')}")
                        st.write("")
            
            # AI Analysis Summary
            if ai_analysis.get('summary'):
                st.subheader("🤖 AI Analysis Summary")
                st.write(ai_analysis['summary'])
            
            # Recommendations
            if ai_analysis.get('recommendations'):
                st.subheader("💡 Recommendations")
                for i, rec in enumerate(ai_analysis['recommendations'], 1):
                    st.write(f"{i}. {rec}")
            
        except Exception as e:
            logger.error(f"Error displaying file scan results: {e}")
            st.error(f"Error displaying results: {e}")
    
    def run_hash_analysis(self, hashes: List[str], config: Dict):
        """Execute hash analysis using VirusTotal"""
        # Implementation for hash analysis
        st.info("Hash analysis functionality - Implementation in progress")
    
    def run_vapt_assessment(self, target: str, port_range: str, vapt_type: str, config: Dict):
        """Execute VAPT assessment"""
        # Implementation for VAPT assessment
        st.info("VAPT assessment functionality - Implementation in progress")
    
    def generate_executive_summary(self, results: Dict) -> str:
        """Generate AI-powered executive summary"""
        # Placeholder implementation
        threats_count = len(results.get('ai_analysis', {}).get('threats', []))
        security_score = results.get('security_score', 0)
        
        if threats_count == 0:
            return f"✅ **Security Assessment Complete**: No threats detected. Current security posture score: {security_score}/100. The scanned environment appears to be clean and secure."
        else:
            return f"⚠️ **Security Assessment Complete**: {threats_count} potential threats identified. Current security posture score: {security_score}/100. Immediate attention recommended for critical findings."
    
    def generate_pdf_report(self):
        """Generate PDF report"""
        try:
            if not st.session_state.scan_results:
                st.error("No scan results available to generate report")
                return
            
            # Show progress
            progress_bar = st.progress(0)
            status_text = st.empty()
            status_text.text("📄 Generating PDF report...")
            
            # Check if ReportLab is available
            try:
                from reportlab.lib.pagesizes import letter, A4
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib.units import inch
                from reportlab.lib import colors
                from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
                REPORTLAB_AVAILABLE = True
            except ImportError:
                REPORTLAB_AVAILABLE = False
                st.error("❌ ReportLab not installed. Please install it with: pip install reportlab")
                return
            
            # Debug: Log scan results structure
            logger.info(f"Scan results type: {type(st.session_state.scan_results)}")
            logger.info(f"Scan results keys: {list(st.session_state.scan_results.keys()) if isinstance(st.session_state.scan_results, dict) else 'Not a dict'}")
            
            # Additional debugging for PDF generation
            try:
                # Test if we can access the data safely
                test_data = st.session_state.scan_results.get('ai_analysis', {})
                logger.info(f"AI analysis type: {type(test_data)}")
                if isinstance(test_data, dict):
                    logger.info(f"AI analysis keys: {list(test_data.keys())}")
                    if 'summary' in test_data:
                        summary = test_data['summary']
                        logger.info(f"Summary type: {type(summary)}")
                        if isinstance(summary, dict):
                            logger.warning("Summary is a dict, converting to string")
                            test_data['summary'] = str(summary)
            except Exception as debug_error:
                logger.error(f"Debug error: {debug_error}")
            
            # Create reports directory
            import tempfile
            import os
            from pathlib import Path
            
            reports_dir = Path.home() / ".sentinelai" / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sentinelai_report_{timestamp}.pdf"
            pdf_path = reports_dir / filename
            
            progress_bar.progress(0.2)
            status_text.text("📊 Creating PDF content...")
            
            # Create PDF document
            doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, topMargin=1*inch, bottomMargin=1*inch)
            story = []
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.HexColor('#1e293b')
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.HexColor('#3b82f6')
            )
            
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=11,
                spaceAfter=6,
                textColor=colors.HexColor('#0f172a')
            )
            
            # Title
            story.append(Paragraph("SentinelAI v2 Security Report", title_style))
            story.append(Spacer(1, 20))
            
            # Report metadata - with safe access
            scan_results = st.session_state.scan_results
            if not isinstance(scan_results, dict):
                st.error("❌ Invalid scan results format")
                return
            
            metadata = scan_results.get('metadata', {})
            if not isinstance(metadata, dict):
                metadata = {}
            
            story.append(Paragraph("Report Information", heading_style))
            report_info = [
                ['Generated At:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Scan Type:', metadata.get('scan_type', 'Unknown')],
                ['Generator:', 'SentinelAI v2.1'],
                ['File Count:', str(metadata.get('file_count', 'N/A'))]
            ]
            
            info_table = Table(report_info, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
            ]))
            
            story.append(info_table)
            story.append(Spacer(1, 20))
            
            # Security Score
            security_score = scan_results.get('security_score', 0)
            story.append(Paragraph("Security Assessment", heading_style))
            story.append(Paragraph(f"Overall Security Score: {security_score}/100", normal_style))
            story.append(Spacer(1, 12))
            
            # Threats Summary - with safe access
            threats = scan_results.get('threats', [])
            if not isinstance(threats, list):
                threats = []
            
            if threats:
                story.append(Paragraph("Threats Detected", heading_style))
                story.append(Paragraph(f"Total Threats Found: {len(threats)}", normal_style))
                
                # Threat severity breakdown
                severity_counts = {}
                for threat in threats:
                    if isinstance(threat, dict):
                        severity = str(threat.get('severity', 'Unknown'))
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                threat_data = [['Severity', 'Count']]
                for severity, count in severity_counts.items():
                    threat_data.append([severity.title(), str(count)])
                
                threat_table = Table(threat_data, colWidths=[2*inch, 1*inch])
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
                ]))
                
                story.append(threat_table)
                story.append(Spacer(1, 20))
                
            # Detailed threats
            story.append(Paragraph("Detailed Threat Analysis", heading_style))
            for i, threat in enumerate(threats[:10]):  # Limit to first 10 threats
                threat_name = str(threat.get('threat_name', 'Unknown Threat'))
                severity = str(threat.get('severity', 'Unknown'))
                description = str(threat.get('description', 'No description available'))
                engine = str(threat.get('engine', 'Unknown'))
                
                # Clean up any problematic characters
                threat_name = threat_name.replace('<', '&lt;').replace('>', '&gt;')
                description = description.replace('<', '&lt;').replace('>', '&gt;')
                
                story.append(Paragraph(f"{i+1}. {threat_name}", normal_style))
                story.append(Paragraph(f"   Severity: {severity.title()}", normal_style))
                story.append(Paragraph(f"   Engine: {engine}", normal_style))
                story.append(Paragraph(f"   Description: {description}", normal_style))
                story.append(Spacer(1, 8))
            else:
                story.append(Paragraph("No threats detected. The scanned environment appears to be clean.", normal_style))
                story.append(Spacer(1, 20))
            
            # AI Analysis Summary - with safe access
            ai_analysis = scan_results.get('ai_analysis', {})
            if not isinstance(ai_analysis, dict):
                ai_analysis = {}
            
            if ai_analysis and ai_analysis.get('summary'):
                summary_data = ai_analysis['summary']
                
                # Handle different data types for summary
                if isinstance(summary_data, dict):
                    # If summary is a dict, extract the text content
                    summary_text = summary_data.get('text', str(summary_data))
                elif isinstance(summary_data, list):
                    # If summary is a list, join the items
                    summary_text = ' '.join([str(item) for item in summary_data])
                else:
                    # If summary is a string or other type, convert to string
                    summary_text = str(summary_data)
                
                # Clean up any problematic characters
                summary_text = summary_text.replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph("AI Analysis Summary", heading_style))
                story.append(Paragraph(summary_text, normal_style))
                story.append(Spacer(1, 20))
            
            # Recommendations
            if ai_analysis and ai_analysis.get('recommendations'):
                recommendations = ai_analysis['recommendations']
                
                # Handle different data types for recommendations
                if isinstance(recommendations, list):
                    story.append(Paragraph("Security Recommendations", heading_style))
                    for i, rec in enumerate(recommendations, 1):
                        # Handle different recommendation formats
                        if isinstance(rec, dict):
                            rec_text = rec.get('text', rec.get('description', str(rec)))
                        else:
                            rec_text = str(rec)
                        
                        rec_text = rec_text.replace('<', '&lt;').replace('>', '&gt;')
                        story.append(Paragraph(f"{i}. {rec_text}", normal_style))
                    story.append(Spacer(1, 20))
                elif isinstance(recommendations, str):
                    # Single recommendation as string
                    story.append(Paragraph("Security Recommendations", heading_style))
                    rec_text = recommendations.replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(f"1. {rec_text}", normal_style))
                    story.append(Spacer(1, 20))
            
            # Footer
            story.append(Spacer(1, 30))
            story.append(Paragraph("Generated by SentinelAI v2 - Advanced Cybersecurity Analysis Platform", 
                                 ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, 
                                              alignment=TA_CENTER, textColor=colors.HexColor('#64748b'))))
            
            progress_bar.progress(0.8)
            status_text.text("📋 Building PDF document...")
            
            # Build PDF with error handling
            try:
                doc.build(story)
                progress_bar.progress(1.0)
                status_text.text("✅ PDF report generated successfully!")
            except Exception as build_error:
                logger.error(f"PDF build error: {build_error}")
                st.error(f"❌ PDF build failed: {str(build_error)}")
                return
            
            # Read the generated PDF
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            
            # Provide download button
            st.download_button(
                label="📄 Download Security Report (PDF)",
                data=pdf_data,
                file_name=filename,
                mime="application/pdf",
                help="Download the comprehensive security report in PDF format"
            )
            
            st.success("✅ PDF report generated successfully! Click the download button above to save the report.")
            
            # Display summary preview
            st.subheader("📋 Report Summary Preview")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Security Score", f"{security_score}/100")
            
            with col2:
                st.metric("Threats Detected", len(threats))
            
            with col3:
                st.metric("Files Scanned", metadata.get('file_count', 'N/A'))
            
            if ai_analysis.get('summary'):
                st.subheader("🤖 AI Analysis Summary")
                st.write(ai_analysis['summary'])
            
        except Exception as e:
            logger.error(f"PDF report generation failed: {e}")
            st.error(f"❌ Report generation failed: {str(e)}")
            
            # Fallback to JSON export
            try:
                combined_report = {
                    'scan_results': st.session_state.scan_results,
                    'metadata': {
                        'generated_at': datetime.now().isoformat(),
                        'generator': 'SentinelAI v2.1',
                        'error': str(e)
                    }
                }
                
                json_data = json.dumps(combined_report, indent=2)
                
                st.download_button(
                    label="📄 Download Report (JSON Format - Error Fallback)",
                    data=json_data,
                    file_name=f"sentinelai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    help="Download the report in JSON format due to PDF generation error"
                )
            except Exception as fallback_error:
                st.error(f"❌ Even fallback generation failed: {str(fallback_error)}")
                
    
    def export_json_report(self):
        """Export JSON report"""
        if st.session_state.scan_results:
            json_data = json.dumps(st.session_state.scan_results, indent=2)
            st.download_button(
                label="Download JSON Report",
                data=json_data,
                file_name=f"sentinelai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    def export_all_data(self):
        """Export all application data"""
        all_data = {
            'scan_results': st.session_state.scan_results,
            'scan_history': st.session_state.scan_history,
            'user_profile': st.session_state.user_profile,
            'export_timestamp': datetime.now().isoformat()
        }
        
        json_data = json.dumps(all_data, indent=2)
        st.download_button(
            label="Download All Data",
            data=json_data,
            file_name=f"sentinelai_data_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    def display_workflow_summary(self, results: Dict):
        """Display comprehensive workflow execution summary"""
        st.success("🎉 **SentinelAI v2 Workflow Complete!**")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Security Score",
                f"{results['security_score']}/100",
                delta=results['security_score'] - 50  # Baseline comparison
            )
        
        with col2:
            threats_count = len(results['ai_analysis'].get('threats', []))
            st.metric(
                "Threats Detected",
                threats_count,
                delta=threats_count if threats_count > 0 else None
            )
        
        with col3:
            files_scanned = len(results['local'].get('files', []))
            st.metric("Files Scanned", files_scanned)
        
        with col4:
            vt_detections = results['virustotal'].get('detections', 0)
            st.metric("VirusTotal Detections", vt_detections)
        
        # Workflow execution trace
        st.subheader("🔄 Workflow Execution Trace")
        workflow_steps = [
            "✅ Config Manager Agent: LLM initialized, API keys secured",
            "✅ Local Scan Agent: SHA256 + fuzzy hashing, ClamAV + YARA scanning",
            "✅ VirusTotal Agent: Hash lookup, file upload <32MB, quota management",
            "✅ VAPT Agent: Host scanning, service fingerprinting, CVE lookup" if results.get('vapt') else "⏭️ VAPT Agent: Skipped (disabled)",
            "✅ AI Reasoning Agent: Threat classification, CVSS scoring, framework mapping",
            "✅ Report Agent: Dashboard generation, PDF/JSON export ready",
            "✅ Gamification: Profile updated, achievements checked"
        ]
        
        for step in workflow_steps:
            st.write(step)
        
        # Display storytelling results
        if results.get('storytelling'):
            st.subheader("📖 AI-Generated Analysis")
            
            story_tab1, story_tab2 = st.tabs(["🎭 Attacker Narrative", "🔬 Analytical Breakdown"])
            
            with story_tab1:
                st.markdown("**Dramatized Intrusion Story:**")
                st.write(results['storytelling']['narrative'])
            
            with story_tab2:
                st.markdown("**MITRE ATT&CK Mapping & TTP Analysis:**")
                st.write(results['storytelling']['analytical'])
        
        # Framework mapping summary
        if results.get('framework_mapping'):
            st.subheader("🎯 Security Framework Alignment")
            
            framework_col1, framework_col2, framework_col3 = st.columns(3)
            
            with framework_col1:
                st.markdown("**CVSS Severity**")
                cvss_data = results['framework_mapping'].get('cvss', {})
                for severity, count in cvss_data.items():
                    st.write(f"• {severity}: {count}")
            
            with framework_col2:
                st.markdown("**MITRE ATT&CK Tactics**")
                mitre_data = results['framework_mapping'].get('mitre', {})
                for tactic, techniques in mitre_data.items():
                    st.write(f"• {tactic}: {len(techniques)} techniques")
            
            with framework_col3:
                st.markdown("**NIST CSF Functions**")
                nist_data = results['framework_mapping'].get('nist', {})
                for function, score in nist_data.items():
                    st.write(f"• {function}: {score}%")
    
    def run(self):
        """Main application entry point"""
        try:
            # Render sidebar configuration
            config = self.render_sidebar()
            
            # Main header
            st.title("🛡️ SentinelAI v2")
            st.markdown("*Enterprise-Grade Cybersecurity Analysis Platform*")
            
            # Render main application tabs
            self.render_main_tabs(config)
            
            # Footer
            st.markdown("---")
            st.markdown(
                "**SentinelAI v2** | "
                "Built with Streamlit, LangChain, and Advanced AI"
            )
            
        except Exception as e:
            logger.error(f"Application error: {str(e)}")
            st.error(f"Application error: {str(e)}")

def load_custom_css():
    st.markdown("""
        <style>
            /* Add custom CSS styles here */
        </style>
    """, unsafe_allow_html=True)

def main():
    """Application entry point"""
    # Load custom CSS
    load_custom_css()
    
    app = SentinelAIApp()
    app.run()

if __name__ == "__main__":
    main()
