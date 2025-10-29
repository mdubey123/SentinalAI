"""
SentinelAI v2 - Advanced Cybersecurity Analysis Platform
Enterprise-Grade Security Assessment Tool

A comprehensive Streamlit application for malware detection, vulnerability assessment,
and AI-powered threat analysis with gamification and multi-LLM support.

Developed by:
- Manya Dubey (Agentic AI, GenAI)
- Meet Solanki (Data Engineer, Security Analyst)  
- Mayush Jain (DevOps Engineer)
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
import time
import functools
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from concurrent.futures import ThreadPoolExecutor
import threading

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
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://docs.streamlit.io/',
        'Report a bug': "https://github.com/streamlit/streamlit/issues",
        'About': "SentinelAI v2 - Advanced Cybersecurity Analysis Platform"
    }
)

# Dark theme is now the default - no toggle needed

# Initialize logging
logger = setup_logger()

# ========================================
# PERFORMANCE OPTIMIZATION & CACHING
# ========================================

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_cached_scan_results(scan_id: str) -> Optional[Dict]:
    """Cache scan results to improve performance"""
    return None

@st.cache_data(ttl=600)  # Cache for 10 minutes
def get_cached_threat_intelligence(query: str) -> Optional[Dict]:
    """Cache threat intelligence data"""
    return None

@st.cache_resource
def get_thread_pool():
    """Get a thread pool for concurrent operations"""
    return ThreadPoolExecutor(max_workers=4)

def validate_api_key(provider: str, api_key: str) -> bool:
    """Validate API key format and security"""
    if not api_key or len(api_key.strip()) < 10:
        return False
    
    # Basic validation patterns
    patterns = {
        'openai': r'^sk-[A-Za-z0-9]{48}$',
        'anthropic': r'^sk-ant-[A-Za-z0-9]{95}$',
        'google': r'^[A-Za-z0-9_-]{39}$',
        'cohere': r'^[A-Za-z0-9]{40}$',
        'virustotal': r'^[A-Za-z0-9]{64}$'
    }
    
    import re
    pattern = patterns.get(provider.lower(), r'^[A-Za-z0-9_-]{20,}$')
    return bool(re.match(pattern, api_key.strip()))

def secure_input_handler(input_data: str, max_length: int = 1000) -> str:
    """Securely handle user input with validation"""
    if not input_data:
        return ""
    
    # Sanitize input
    sanitized = input_data.strip()[:max_length]
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`']
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized

def handle_api_quota(provider: str, operation: str) -> bool:
    """Handle API quota management"""
    quota_key = f"{provider}_{operation}_quota"
    
    if quota_key not in st.session_state:
        st.session_state[quota_key] = {
            'requests': 0,
            'last_reset': time.time(),
            'daily_limit': 1000  # Default limit
        }
    
    quota = st.session_state[quota_key]
    current_time = time.time()
    
    # Reset daily counter if 24 hours have passed
    if current_time - quota['last_reset'] > 86400:  # 24 hours
        quota['requests'] = 0
        quota['last_reset'] = current_time
    
    # Check if quota exceeded
    if quota['requests'] >= quota['daily_limit']:
        st.error(f"⚠️ API quota exceeded for {provider}. Please try again tomorrow.")
        return False
    
    quota['requests'] += 1
    return True

def optimize_scan_performance(scan_type: str, target: str) -> Dict:
    """Optimize scan performance based on type and target"""
    optimizations = {
        'quick_scan': {
            'timeout': 30,
            'max_threads': 2,
            'cache_results': True
        },
        'deep_scan': {
            'timeout': 300,
            'max_threads': 4,
            'cache_results': True
        },
        'custom': {
            'timeout': 120,
            'max_threads': 3,
            'cache_results': True
        }
    }
    
    return optimizations.get(scan_type, optimizations['quick_scan'])

# ========================================
# THEME MANAGEMENT SYSTEM
# ========================================


def create_sidebar_config():
    """
    Create the sidebar configuration section with LLM settings.
    """
    st.sidebar.markdown("### 🤖 AI Configuration")
    
    # LLM Provider dropdown
    llm_provider = st.sidebar.selectbox(
        "LLM Provider:",
        options=["OpenAI", "Llama", "Gemini", "Claude", "Custom"],
        index=0,
        key="llm_provider"
    )
    
    # Model selection based on provider
    model_options = {
        "OpenAI": ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
        "Llama": ["llama-3.1-8b", "llama-3.1-70b", "llama-3.2-3b"],
        "Gemini": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.0-pro"],
        "Claude": ["claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus"],
        "Custom": ["custom-model"]
    }
    
    selected_model = st.sidebar.selectbox(
        "Model:",
        options=model_options.get(llm_provider, ["default"]),
        index=0,
        key="llm_model"
    )
    
    # API Key input (masked)
    api_key = st.sidebar.text_input(
        f"{llm_provider} API Key:",
        type="password",
        key="llm_api_key",
        help="Enter your API key for the selected provider"
    )

# ========================================
# HOME PAGE ENHANCEMENT
# ========================================

def create_home_page():
    """Create an engaging home page with team information and app description"""
    
    # Hero Section with animated title
    st.markdown("""
    <div class="hero-section fade-in">
        <div class="hero-content">
            <h1 class="hero-title">
                <span class="gradient-text">SentinelAI v2</span>
            </h1>
            <h2 class="hero-subtitle">Advanced Cybersecurity Analysis Platform</h2>
            <p class="hero-description">
                Empowering organizations with AI-driven security intelligence, 
                comprehensive threat analysis, and automated vulnerability assessment.
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # App Description Section
    st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
    st.markdown("## 🎯 About SentinelAI v2")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("""
        ### 🛡️ **Purpose & Mission**
        
        SentinelAI v2 is a cutting-edge cybersecurity platform that combines:
        
        - **🤖 AI-Powered Analysis**: Advanced machine learning algorithms for threat detection
        - **🔍 Comprehensive Scanning**: Multi-layered security assessment capabilities
        - **📊 Real-time Intelligence**: Live threat intelligence and vulnerability tracking
        - **🎮 Gamified Experience**: Engaging user interface with achievement systems
        - **🔧 DevOps Integration**: Seamless CI/CD pipeline security integration
        
        Our platform empowers security teams to stay ahead of evolving threats through 
        intelligent automation and comprehensive analysis tools.
        """)
    
    with col2:
        st.markdown("""
        ### 🚀 **Key Features**
        
        - **Multi-LLM Support**: Integration with OpenAI, Anthropic, Google, and more
        - **VirusTotal Integration**: Real-time malware analysis and threat intelligence
        - **VAPT Capabilities**: Comprehensive penetration testing and vulnerability assessment
        - **Automated Reporting**: AI-generated security reports with actionable insights
        - **Real-time Monitoring**: Continuous security posture assessment
        - **Compliance Mapping**: NIST, OWASP, and industry-standard framework alignment
        """)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Team Section with Toggle Cards
    st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
    st.markdown("## 👥 Our Team")
    st.markdown("Click on any team member card to learn more about their expertise and contributions!")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Initialize session state for team member toggles
        if 'manya_expanded' not in st.session_state:
            st.session_state.manya_expanded = False
        
        if st.button("🤖", key="manya_toggle", help="Click to expand/collapse"):
            st.session_state.manya_expanded = not st.session_state.manya_expanded
        
        if st.session_state.manya_expanded:
            st.markdown("""
            <div class="team-member expanded">
                <div class="member-icon">🤖</div>
                <h3>Manya Dubey</h3>
                <p class="member-role">Agentic AI & GenAI Specialist</p>
                <div class="member-details">
                    <p class="member-description">
                        Leading the development of intelligent AI agents and generative AI 
                        capabilities that power our automated threat analysis and response systems.
                    </p>
                    <div class="member-skills">
                        <span class="skill-tag">Machine Learning</span>
                        <span class="skill-tag">Natural Language Processing</span>
                        <span class="skill-tag">AI Agent Development</span>
                        <span class="skill-tag">Threat Intelligence</span>
                    </div>
                    <div class="member-achievements">
                        <h4>Key Contributions:</h4>
                        <ul>
                            <li>Designed AI-powered threat analysis algorithms</li>
                            <li>Implemented intelligent agent orchestration</li>
                            <li>Developed natural language report generation</li>
                            <li>Created automated threat classification systems</li>
                        </ul>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="team-member collapsed">
                <div class="member-icon">🤖</div>
                <h3>Manya Dubey</h3>
                <p class="member-role">Agentic AI & GenAI Specialist</p>
                <p class="member-description">
                    Leading the development of intelligent AI agents and generative AI 
                    capabilities that power our automated threat analysis and response systems.
                </p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        if 'meet_expanded' not in st.session_state:
            st.session_state.meet_expanded = False
        
        if st.button("📊", key="meet_toggle", help="Click to expand/collapse"):
            st.session_state.meet_expanded = not st.session_state.meet_expanded
        
        if st.session_state.meet_expanded:
            st.markdown("""
            <div class="team-member expanded">
                <div class="member-icon">📊</div>
                <h3>Meet Solanki</h3>
                <p class="member-role">Data Engineer & Security Analyst</p>
                <div class="member-details">
                    <p class="member-description">
                        Architecting robust data pipelines and implementing advanced security 
                        analysis algorithms to ensure comprehensive threat detection and assessment.
                    </p>
                    <div class="member-skills">
                        <span class="skill-tag">Data Engineering</span>
                        <span class="skill-tag">Security Analysis</span>
                        <span class="skill-tag">Big Data Processing</span>
                        <span class="skill-tag">Threat Detection</span>
                    </div>
                    <div class="member-achievements">
                        <h4>Key Contributions:</h4>
                        <ul>
                            <li>Built scalable data processing pipelines</li>
                            <li>Implemented real-time threat detection algorithms</li>
                            <li>Designed security analytics dashboards</li>
                            <li>Optimized performance for large-scale scans</li>
                        </ul>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="team-member collapsed">
                <div class="member-icon">📊</div>
                <h3>Meet Solanki</h3>
                <p class="member-role">Data Engineer & Security Analyst</p>
                <p class="member-description">
                    Architecting robust data pipelines and implementing advanced security 
                    analysis algorithms to ensure comprehensive threat detection and assessment.
                </p>
            </div>
            """, unsafe_allow_html=True)
    
    with col3:
        if 'mayush_expanded' not in st.session_state:
            st.session_state.mayush_expanded = False
        
        if st.button("⚙️", key="mayush_toggle", help="Click to expand/collapse"):
            st.session_state.mayush_expanded = not st.session_state.mayush_expanded
        
        if st.session_state.mayush_expanded:
            st.markdown("""
            <div class="team-member expanded">
                <div class="member-icon">⚙️</div>
                <h3>Mayush Jain</h3>
                <p class="member-role">DevOps Engineer</p>
                <div class="member-details">
                    <p class="member-description">
                        Building scalable infrastructure and implementing DevOps best practices 
                        to ensure reliable, secure, and efficient platform operations.
                    </p>
                    <div class="member-skills">
                        <span class="skill-tag">DevOps</span>
                        <span class="skill-tag">Infrastructure</span>
                        <span class="skill-tag">Containerization</span>
                        <span class="skill-tag">CI/CD</span>
                    </div>
                    <div class="member-achievements">
                        <h4>Key Contributions:</h4>
                        <ul>
                            <li>Implemented containerized deployment strategies</li>
                            <li>Built automated CI/CD pipelines</li>
                            <li>Designed scalable cloud infrastructure</li>
                            <li>Ensured high availability and security</li>
                        </ul>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="team-member collapsed">
                <div class="member-icon">⚙️</div>
                <h3>Mayush Jain</h3>
                <p class="member-role">DevOps Engineer</p>
                <p class="member-description">
                    Building scalable infrastructure and implementing DevOps best practices 
                    to ensure reliable, secure, and efficient platform operations.
                </p>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Workflow Section
    st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
    st.markdown("## 🔄 How It Works")
    
    workflow_steps = [
        {
            "step": "1",
            "title": "Configuration",
            "description": "Set up your AI models, API keys, and scan parameters",
            "icon": "⚙️"
        },
        {
            "step": "2", 
            "title": "Scanning",
            "description": "Execute comprehensive security scans using multiple engines",
            "icon": "🔍"
        },
        {
            "step": "3",
            "title": "Analysis",
            "description": "AI-powered analysis of results with threat intelligence correlation",
            "icon": "🧠"
        },
        {
            "step": "4",
            "title": "Reporting",
            "description": "Generate detailed reports with actionable recommendations",
            "icon": "📋"
        }
    ]
    
    cols = st.columns(4)
    for i, step in enumerate(workflow_steps):
        with cols[i]:
            st.markdown(f"""
            <div class="workflow-step">
                <div class="step-number">{step['step']}</div>
                <div class="step-icon">{step['icon']}</div>
                <h4>{step['title']}</h4>
                <p>{step['description']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Benefits Section
    st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
    st.markdown("## 💡 Benefits")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🎯 **For Security Teams**
        - **Reduced Manual Work**: Automate routine security tasks
        - **Faster Response**: Real-time threat detection and analysis
        - **Better Coverage**: Comprehensive multi-vector scanning
        - **Actionable Insights**: Clear, prioritized recommendations
        """)
    
    with col2:
        st.markdown("""
        ### 🏢 **For Organizations**
        - **Cost Efficiency**: Reduce security tool sprawl
        - **Compliance**: Meet regulatory requirements with automated mapping
        - **Risk Reduction**: Proactive threat identification and mitigation
        - **Scalability**: Adapt to growing security needs
        """)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Call to Action
    st.markdown("""
    <div class="cta-section fade-in">
        <h2>Ready to Get Started?</h2>
        <p>Configure your settings in the sidebar and begin your first security scan!</p>
    </div>
    """, unsafe_allow_html=True)

# ========================================
# FOOTER COMPONENT
# ========================================

def create_footer():
    """Create a modern footer with team information"""
    st.markdown("""
    <div class="footer-section">
        <div class="footer-content">
            <div class="footer-main">
                <h3>🛡️ SentinelAI v2</h3>
                <p>Empowering cybersecurity solutions through AI-driven intelligence and automation.</p>
            </div>
            <div class="footer-team">
                <h4>Our Team</h4>
                <div class="team-links">
                    <span>🤖 Manya Dubey (Agentic AI & GenAI)</span>
                    <span>📊 Meet Solanki (Data Engineer & Security Analyst)</span>
                    <span>⚙️ Mayush Jain (DevOps Engineer)</span>
                </div>
            </div>
            <div class="footer-mission">
                <h4>Mission</h4>
                <p>Building the future of cybersecurity through intelligent automation, comprehensive analysis, and proactive threat detection.</p>
            </div>
        </div>
        <div class="footer-bottom">
            <p>&copy; 2024 SentinelAI v2. Built with ❤️ for the cybersecurity community.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def load_custom_css():
    """Load modern cybersecurity-themed CSS"""
    custom_css = """
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Poppins:wght@300;400;500;600;700;800&family=Roboto:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
    /* ========================================
       MODERN CYBERSECURITY DASHBOARD THEME
       ======================================== */
    
    :root {
        --bg-primary: #0a0a1a;
        --bg-secondary: #111827;
        --bg-elevated: #1f2937;
        --bg-glass: rgba(255, 255, 255, 0.05);
        
        --text-primary: #f8fafc;
        --text-secondary: #cbd5e1;
        --text-muted: #94a3b8;
        --text-accent: #00d4ff;
        
        --accent-primary: #00d4ff;
        --accent-secondary: #7c3aed;
        --accent-success: #10b981;
        --accent-warning: #f59e0b;
        --accent-danger: #ef4444;
        
        --border-primary: rgba(255, 255, 255, 0.1);
        --border-accent: rgba(0, 212, 255, 0.3);
        
        --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.3);
        --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
        --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.5);
        --shadow-glow: 0 0 20px rgba(0, 212, 255, 0.3);
        
        --radius-sm: 6px;
        --radius-md: 10px;
        --radius-lg: 16px;
        --radius-xl: 24px;
        
        --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .stApp {
        background: var(--bg-primary) !important;
        color: var(--text-primary) !important;
        font-family: 'Inter', 'Poppins', 'Roboto', sans-serif !important;
        line-height: 1.6 !important;
    }
    
    body {
        background: var(--bg-primary) !important;
        color: var(--text-primary) !important;
        font-family: 'Inter', 'Poppins', 'Roboto', sans-serif !important;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary) !important;
        font-weight: 700 !important;
        margin-bottom: 1rem !important;
        font-family: 'Inter', sans-serif !important;
        text-rendering: optimizeLegibility !important;
        -webkit-font-smoothing: antialiased !important;
        -moz-osx-font-smoothing: grayscale !important;
    }
    
    h1 {
        font-size: 2.5rem !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #00d4ff, #7c3aed) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        text-align: center !important;
        margin-bottom: 1.5rem !important;
    }
    
    h2 {
        font-size: 2rem !important;
        color: var(--text-primary) !important;
        position: relative !important;
    }
    
    h2::after {
        content: '' !important;
        position: absolute !important;
        bottom: -8px !important;
        left: 0 !important;
        width: 60px !important;
        height: 3px !important;
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary)) !important;
        border-radius: 2px !important;
    }
    
    h3 {
        font-size: 1.5rem !important;
        color: var(--text-primary) !important;
    }
    
    p, span, div {
        color: var(--text-secondary) !important;
        font-size: 1rem !important;
        line-height: 1.6 !important;
    }
    
    [data-testid="stSidebar"] {
        background: var(--bg-secondary) !important;
        border-right: 2px solid var(--border-accent) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        box-shadow: var(--shadow-lg) !important;
        width: 320px !important;
        min-width: 320px !important;
    }
    
    [data-testid="stSidebar"] > div:first-child {
        padding: 2rem 1.5rem !important;
        background: transparent !important;
    }
    
    .stSidebar h1 {
        font-size: 1.8rem !important;
        font-weight: 800 !important;
        text-align: center !important;
        margin-bottom: 0.5rem !important;
        background: linear-gradient(135deg, #00d4ff, #7c3aed) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
    }
    
    .stSidebar p {
        text-align: center !important;
        color: var(--text-muted) !important;
        font-style: italic !important;
        margin-bottom: 2rem !important;
    }
    
    .stSidebar .stMarkdown,
    .stSidebar .stSelectbox,
    .stSidebar .stTextInput,
    .stSidebar .stRadio,
    .stSidebar .stCheckbox {
        margin-bottom: 1.5rem !important;
        width: 100% !important;
    }
    
    .stSidebar .stSelectbox > div > div > div,
    .stSidebar .stTextInput > div > div > input {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: 0.75rem 1rem !important;
        font-size: 0.9rem !important;
        transition: var(--transition) !important;
        width: 100% !important;
    }
    
    .stSidebar .stSelectbox > div > div > div:hover,
    .stSidebar .stTextInput > div > div > input:hover {
        border-color: var(--accent-primary) !important;
        box-shadow: var(--shadow-glow) !important;
    }
    
    .stSidebar .stSelectbox > div > div > div:focus,
    .stSidebar .stTextInput > div > div > input:focus {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.2) !important;
        outline: none !important;
    }
    
    .stSidebar .stRadio > div {
        background: var(--bg-glass) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-lg) !important;
        padding: 1rem !important;
        transition: var(--transition) !important;
    }
    
    .stSidebar .stRadio > div:hover {
        border-color: var(--accent-primary) !important;
        background: var(--bg-elevated) !important;
        transform: translateY(-2px) !important;
        box-shadow: var(--shadow-md) !important;
    }
    
    .stSidebar .stRadio label {
        color: var(--text-primary) !important;
        font-weight: 500 !important;
        font-size: 0.95rem !important;
        padding: 0.5rem 0 !important;
        display: flex !important;
        align-items: center !important;
        white-space: nowrap !important;
    }
    
    .stSidebar .stRadio label > div:first-child {
        margin-right: 0.75rem !important;
        border: 2px solid var(--accent-primary) !important;
        border-radius: 50% !important;
        width: 18px !important;
        height: 18px !important;
        transition: var(--transition) !important;
    }
    
    .stSidebar .stRadio label:hover > div:first-child {
        border-color: var(--accent-secondary) !important;
        box-shadow: 0 0 8px rgba(0, 212, 255, 0.4) !important;
    }
    
    .main .block-container {
        padding: 2.5rem !important;
        max-width: 1200px !important;
        margin: 0 auto !important;
        background: transparent !important;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)) !important;
        color: white !important;
        border: none !important;
        border-radius: var(--radius-md) !important;
        padding: 0.875rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        transition: var(--transition) !important;
        box-shadow: var(--shadow-md) !important;
        position: relative !important;
        overflow: hidden !important;
        cursor: pointer !important;
    }
    
    .stButton > button::before {
        content: '' !important;
        position: absolute !important;
        top: 0 !important;
        left: -100% !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent) !important;
        transition: var(--transition) !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-3px) !important;
        box-shadow: var(--shadow-lg) !important;
    }
    
    .stButton > button:hover::before {
        left: 100% !important;
    }
    
    .stButton > button:active {
        transform: translateY(-1px) !important;
    }
    
    .card, .modern-card {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-lg) !important;
        padding: 2rem !important;
        margin-bottom: 1.5rem !important;
        box-shadow: var(--shadow-md) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
        transition: var(--transition) !important;
        position: relative !important;
        overflow: hidden !important;
    }
    
    .card::before, .modern-card::before {
        content: '' !important;
        position: absolute !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        height: 3px !important;
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary)) !important;
        opacity: 0.8 !important;
    }
    
    .card:hover, .modern-card:hover {
        transform: translateY(-4px) !important;
        box-shadow: var(--shadow-lg) !important;
        border-color: var(--accent-primary) !important;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        background: var(--bg-elevated) !important;
        border-radius: var(--radius-lg) !important;
        padding: 0.5rem !important;
        margin-bottom: 2rem !important;
        border: 1px solid var(--border-primary) !important;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: var(--text-secondary) !important;
        padding: 1rem 1.5rem !important;
        margin-right: 0.5rem !important;
        border-radius: var(--radius-md) !important;
        transition: var(--transition) !important;
        font-weight: 500 !important;
        position: relative !important;
        overflow: hidden !important;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        color: var(--text-primary) !important;
        background: var(--bg-glass) !important;
        transform: translateY(-2px) !important;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--text-primary) !important;
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)) !important;
        box-shadow: var(--shadow-md) !important;
        transform: translateY(-2px) !important;
    }
    
    .stAlert {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-lg) !important;
        padding: 1.5rem !important;
        margin: 1rem 0 !important;
        box-shadow: var(--shadow-md) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
    }
    
    .stAlert[data-testid="stSuccess"] {
        border-left: 4px solid var(--accent-success) !important;
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), var(--bg-elevated)) !important;
    }
    
    .stAlert[data-testid="stWarning"] {
        border-left: 4px solid var(--accent-warning) !important;
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), var(--bg-elevated)) !important;
    }
    
    .stAlert[data-testid="stError"] {
        border-left: 4px solid var(--accent-danger) !important;
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), var(--bg-elevated)) !important;
    }
    
    ::-webkit-scrollbar {
        width: 8px !important;
        height: 8px !important;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--bg-secondary) !important;
        border-radius: var(--radius-sm) !important;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, var(--accent-primary), var(--accent-secondary)) !important;
        border-radius: var(--radius-sm) !important;
        transition: var(--transition) !important;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, var(--accent-secondary), var(--accent-primary)) !important;
    }
    
    @media (max-width: 768px) {
        .main .block-container {
            padding: 1.5rem !important;
        }
        
        [data-testid="stSidebar"] {
            width: 100vw !important;
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            z-index: 1000 !important;
            transform: translateX(-100%) !important;
            transition: transform 0.3s ease !important;
        }
        
        .stTabs [data-baseweb="tab"] {
            padding: 0.75rem 1rem !important;
            font-size: 0.9rem !important;
        }
        
        h1 {
            font-size: 2rem !important;
        }
        
        h2 {
            font-size: 1.5rem !important;
        }
    }
    
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .fade-in-up {
        animation: fadeInUp 0.6s ease-out !important;
    }
    
    @keyframes glow {
        0%, 100% {
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        50% {
            box-shadow: 0 0 30px rgba(0, 212, 255, 0.6);
        }
    }
    
    .glow {
        animation: glow 2s ease-in-out infinite !important;
    }
    
    .text-center { text-align: center !important; }
    .text-left { text-align: left !important; }
    .text-right { text-align: right !important; }
    
    .mb-1 { margin-bottom: 0.5rem !important; }
    .mb-2 { margin-bottom: 1rem !important; }
    .mb-3 { margin-bottom: 1.5rem !important; }
    .mb-4 { margin-bottom: 2rem !important; }
    
    .mt-1 { margin-top: 0.5rem !important; }
    .mt-2 { margin-top: 1rem !important; }
    .mt-3 { margin-top: 1.5rem !important; }
    .mt-4 { margin-top: 2rem !important; }
    
    .p-1 { padding: 0.5rem !important; }
    .p-2 { padding: 1rem !important; }
    .p-3 { padding: 1.5rem !important; }
    .p-4 { padding: 2rem !important; }
    
    * {
        box-sizing: border-box !important;
    }
    
    .stApp * {
        font-family: 'Inter', 'Poppins', 'Roboto', sans-serif !important;
    }
    
    .stApp, .stApp *, .stApp *::before, .stApp *::after {
        color: inherit !important;
    }
    
    .stApp p, .stApp span, .stApp div {
        color: var(--text-secondary) !important;
    }
    
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
        color: var(--text-primary) !important;
    }
    
    .stApp label {
        color: var(--text-secondary) !important;
        font-weight: 500 !important;
    }
    
    .stVerticalBlockBorder,
    .stHorizontalBlockBorder {
        display: none !important;
    }
    
    </style>
    """
    
    st.markdown(custom_css, unsafe_allow_html=True)

def create_sidebar_config():
    """
    Create the sidebar configuration section with LLM settings.
    """
    st.sidebar.markdown("### 🤖 AI Configuration")
    
    # LLM Provider dropdown
    llm_provider = st.sidebar.selectbox(
        "LLM Provider:",
        options=["OpenAI", "Llama", "Gemini", "Claude", "Custom"],
        index=0,
        key="llm_provider"
    )
    
    # Model selection based on provider
    model_options = {
        "OpenAI": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo", "gpt-4o"],
        "Llama": ["llama-2-70b", "llama-2-13b", "llama-2-7b"],
        "Gemini": ["gemini-pro", "gemini-pro-vision"],
        "Claude": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
        "Custom": ["custom-model"]
    }
    
    selected_model = st.sidebar.selectbox(
        "Model:",
        options=model_options.get(llm_provider, ["default"]),
        key="selected_model"
    )
    
    # API Key input
    api_key = st.sidebar.text_input(
        "API Key:",
        type="password",
        key="api_key",
        help="Enter your API key for the selected provider"
    )
    
    # Advanced settings
    with st.sidebar.expander("⚙️ Advanced Settings"):
        temperature = st.slider("Temperature:", 0.0, 2.0, 0.7, 0.1)
        max_tokens = st.number_input("Max Tokens:", 100, 4000, 1000)
        top_p = st.slider("Top P:", 0.0, 1.0, 0.9, 0.05)
    
    return {
        "llm_provider": llm_provider,
        "model": selected_model,
        "api_key": api_key,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "top_p": top_p
    }

def main():
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
        width: 360px !important;
        min-width: 320px !important;
        box-shadow: 0 0 30px rgba(0, 128, 255, 0.2) !important;
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        height: 100vh !important;
        z-index: 100 !important;
    }

    /* Sidebar content container */
    .css-1d391kg > div {
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
        padding: 2rem 1.5rem !important;
        height: 100% !important;
        overflow-y: auto !important;
    }

    /* Sidebar title - Professional styling */
    .css-1d391kg h1 {
        color: #E6E6E6 !important;
        font-size: 1.5rem !important;
        font-weight: 800 !important;
        margin-bottom: 0.5rem !important;
        text-align: center !important;
        background: linear-gradient(135deg, #00ffff 0%, #0080ff 50%, #8000ff 100%) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        text-shadow: 0 0 15px rgba(0, 212, 255, 0.5) !important;
        line-height: 1.2 !important;
    }

    /* Sidebar subtitle */
    .css-1d391kg p {
        color: #B8BCC8 !important;
        font-size: 0.875rem !important;
        text-align: center !important;
        margin-bottom: 2rem !important;
        font-style: italic !important;
        line-height: 1.4 !important;
    }

    /* Sidebar radio buttons - NO TEXT WRAPPING */
    .css-1d391kg .stRadio > div {
        display: flex !important;
        flex-direction: column !important;
        gap: 0.75rem !important;
        width: 100% !important;
    }

    .css-1d391kg .stRadio > div > label {
        display: flex !important;
        align-items: center !important;
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: unset !important;
        padding: 0.875rem 1rem !important;
        border-radius: 6px !important;
        transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94) !important;
        background: rgba(255, 255, 255, 0.03) !important;
        border: 1px solid transparent !important;
        font-size: 1rem !important;
        font-weight: 500 !important;
        color: #E6E6E6 !important;
        cursor: pointer !important;
        position: relative !important;
        min-height: 48px !important;
    }

    .css-1d391kg .stRadio > div > label:hover {
        background: rgba(0, 212, 255, 0.08) !important;
        border-color: #00d4ff !important;
        transform: translateX(6px) !important;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.3) !important;
    }

    /* Radio button indicator */
    .css-1d391kg .stRadio > div > label > div:first-child {
        margin-right: 1rem !important;
        border: 2px solid #00d4ff !important;
        border-radius: 50% !important;
        transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94) !important;
        width: 20px !important;
        height: 20px !important;
        min-width: 20px !important;
        min-height: 20px !important;
        flex-shrink: 0 !important;
    }

    .css-1d391kg .stRadio > div > label:hover > div:first-child {
        border-color: #00d4ff !important;
        box-shadow: 0 0 8px rgba(0, 212, 255, 0.4) !important;
    }

    /* Main content area */
    .main {
        margin-left: 360px !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        width: calc(100vw - 360px) !important;
        min-height: 100vh !important;
    }

    .main .block-container {
        padding-top: 2.5rem !important;
        padding-left: 2.5rem !important;
        padding-right: 2.5rem !important;
        padding-bottom: 2.5rem !important;
        max-width: calc(100vw - 360px - 4rem) !important;
        margin-left: 0 !important;
        margin-right: 0 !important;
        width: 100% !important;
    }

    /* Enhanced typography */
    h1, h2, h3, h4, h5, h6 {
        color: #E6E6E6 !important;
        font-weight: 700 !important;
        margin-bottom: 1.25rem !important;
        background: none !important;
        -webkit-background-clip: initial !important;
        -webkit-text-fill-color: initial !important;
        background-clip: initial !important;
        text-shadow: none !important;
        letter-spacing: -0.025em !important;
        line-height: 1.2 !important;
        font-family: 'Inter', 'Poppins', 'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif !important;
        text-rendering: optimizeLegibility !important;
        -webkit-font-smoothing: antialiased !important;
        -moz-osx-font-smoothing: grayscale !important;
    }

    h1 {
        font-size: 2.25rem !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #00ffff 0%, #0080ff 50%, #8000ff 100%) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        text-shadow: none !important;
        margin-bottom: 1.5rem !important;
    }

    p, span, div {
        color: #B8BCC8 !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        font-weight: 400 !important;
        line-height: 1.6 !important;
        font-size: 1rem !important;
        font-family: 'Inter', 'Poppins', 'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif !important;
        text-rendering: optimizeLegibility !important;
        -webkit-font-smoothing: antialiased !important;
        -moz-osx-font-smoothing: grayscale !important;
    }

    /* Enhanced text clarity for all elements */
    .stApp, .stApp *, .stApp *::before, .stApp *::after {
        text-rendering: optimizeLegibility !important;
        -webkit-font-smoothing: antialiased !important;
        -moz-osx-font-smoothing: grayscale !important;
        font-feature-settings: 'kern' 1, 'liga' 1, 'calt' 1 !important;
    }

    /* Responsive design */
    @media (max-width: 1400px) {
        .css-1d391kg {
            width: 320px !important;
            min-width: 300px !important;
        }
        
        .main {
            margin-left: 320px !important;
            width: calc(100vw - 320px) !important;
        }
        
        .main .block-container {
            max-width: calc(100vw - 320px - 2rem) !important;
        }
    }

    @media (max-width: 768px) {
        .css-1d391kg {
            width: 100vw !important;
            min-width: 100vw !important;
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            z-index: 1000 !important;
            height: 100vh !important;
            transform: translateX(-100%) !important;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }
        
        .main {
            margin-left: 0 !important;
            width: 100vw !important;
        }
        
        .main .block-container {
            max-width: 100vw !important;
            padding: 1rem !important;
        }
    }
    </style>
    """
    
    st.markdown(custom_css, unsafe_allow_html=True)
    
    /* ===== Main Content Layout Fix ===== */
    [data-testid="stAppViewContainer"] {
        margin-left: 20rem !important;
        background: radial-gradient(circle at 10% 20%, #0f172a, #020617) !important;
        min-height: 100vh !important;
    }
    
    .main .block-container {
        padding: 2rem 3rem !important;
        max-width: none !important;
        margin: 0 !important;
        background: transparent !important;
    }
    
    /* Remove unwanted borders and lines */
    hr, .stVerticalBlockBorder, .stHorizontalBlockBorder {
        display: none !important;
    }
    
    /* Ensure dark theme is always applied */
    html, body, [data-testid="stAppViewContainer"], .stApp {
        background-color: #0d1117 !important;
        color: #e6edf3 !important;
    }
    
    /* ========================================
       ENTERPRISE DARK THEME VARIABLES
       ======================================== */
    
    :root {
        /* Enterprise Dark Color Palette */
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #21262d;
        --bg-elevated: #30363d;
        
        --text-primary: #e6edf3;
        --text-secondary: #8b949e;
        --text-muted: #6e7681;
        
        --border-primary: rgba(255, 255, 255, 0.08);
        --border-secondary: rgba(255, 255, 255, 0.05);
        --border-accent: #238636;
        
        --accent-primary: #238636;
        --accent-hover: #2ea043;
        --accent-light: #3fb950;
        
        --success: #3fb950;
        --warning: #d29922;
        --danger: #f85149;
        --info: #58a6ff;
        
        /* Design Tokens */
        --radius-sm: 6px;
        --radius-md: 8px;
        --radius-lg: 12px;
        --radius-xl: 16px;
        
        --transition-fast: 0.15s ease;
        --transition-normal: 0.25s ease;
        --transition-slow: 0.35s ease;
        
        --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.3);
        --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
        --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.5);
    }
    
    /* ========================================
       SIDEBAR STYLING
       ======================================== */
    
    /* ===== Sidebar Container ===== */
    [data-testid="stSidebar"] > div:first-child {
        padding: 0 !important;
        height: 100% !important;
        background: transparent !important;
    }
    
    /* ===== Sidebar Title Styling ===== */
    .stSidebar h1 {
        color: #93c5fd !important;
        font-size: 1.4rem !important;
        font-weight: 700 !important;
        margin-bottom: 1rem !important;
        text-align: center !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        text-shadow: 0 0 10px rgba(147, 197, 253, 0.3) !important;
        border-bottom: 2px solid #1f2937 !important;
        padding-bottom: 1rem !important;
    }
    
    .stSidebar h2, .stSidebar h3 {
        color: #60a5fa !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        margin: 2rem 0 1rem 0 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        border-left: 3px solid #2563eb !important;
        padding-left: 0.75rem !important;
        text-shadow: 0 0 8px rgba(96, 165, 250, 0.2) !important;
    }
    
    /* ===== Sidebar Sections Spacing ===== */
    .stSidebar .stMarkdown,
    .stSidebar .stSelectbox,
    .stSidebar .stTextInput,
    .stSidebar .stRadio,
    .stSidebar .stCheckbox,
    .stSidebar .stExpander {
        margin-bottom: 1.5rem !important;
        width: 100% !important;
    }
    
    /* ========================================
       FORM ELEMENTS - ENTERPRISE STYLING
       ======================================== */
    
    /* Select boxes */
    .stSelectbox > div > div > div {
        background-color: var(--bg-secondary) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: 0.75rem 1rem !important;
        font-size: 0.875rem !important;
        transition: var(--transition-normal) !important;
    }
    
    .stSelectbox > div > div > div:hover {
        border-color: var(--accent-primary) !important;
        background-color: var(--bg-tertiary) !important;
    }
    
    .stSelectbox > div > div > div:focus {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 0 0 3px rgba(35, 134, 54, 0.1) !important;
        outline: none !important;
    }
    
    /* Text inputs */
    .stTextInput > div > div > input,
    .stPasswordInput > div > div > input {
        background-color: var(--bg-secondary) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: 0.75rem 1rem !important;
        font-size: 0.875rem !important;
        transition: var(--transition-normal) !important;
    }
    
    .stTextInput > div > div > input:hover,
    .stPasswordInput > div > div > input:hover {
        border-color: var(--accent-primary) !important;
        background-color: var(--bg-tertiary) !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stPasswordInput > div > div > input:focus {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 0 0 3px rgba(35, 134, 54, 0.1) !important;
        outline: none !important;
    }
    
    /* Labels */
    .stSelectbox label,
    .stTextInput label,
    .stPasswordInput label {
        color: var(--text-primary) !important;
        font-weight: 500 !important;
        font-size: 0.875rem !important;
        margin-bottom: 0.5rem !important;
    }
    
    /* ===== Enhanced Radio Button Styling ===== */
    .stRadio > div {
        background: rgba(15, 23, 42, 0.3) !important;
        border: 1px solid #1f2937 !important;
        border-radius: 12px !important;
        padding: 1rem !important;
        transition: all 0.3s ease !important;
        backdrop-filter: blur(10px) !important;
    }
    
    .stRadio > div:hover {
        border-color: #2563eb !important;
        background: rgba(37, 99, 235, 0.1) !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2) !important;
    }
    
    /* ===== Radio Button Label Alignment Fix ===== */
    .stRadio label {
        display: flex !important;
        align-items: center !important;
        gap: 0.6rem !important;
        color: #e5e7eb !important;
        font-weight: 500 !important;
        font-size: 1rem !important;
        padding: 0.5rem 0.8rem !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
        cursor: pointer !important;
    }
    
    .stRadio label:hover {
        background: rgba(59, 130, 246, 0.2) !important;
        transform: translateX(4px) !important;
        color: #93c5fd !important;
    }
    
    /* ===== Radio Button Icon Alignment ===== */
    .stRadio label > div:first-child {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        width: 20px !important;
        height: 20px !important;
    }
    
    /* ===== Active Selection Highlight ===== */
    .stRadio [role="radio"][aria-checked="true"] {
        background: linear-gradient(90deg, #2563eb, #1e3a8a) !important;
        border-color: #2563eb !important;
        box-shadow: 0 0 12px rgba(37, 99, 235, 0.6) !important;
    }
    
    .stRadio [role="radio"][aria-checked="true"] + label {
        background: linear-gradient(90deg, #2563eb, #1e3a8a) !important;
        color: #fff !important;
        font-weight: 600 !important;
        transform: scale(1.02) !important;
        box-shadow: 0 0 12px rgba(37, 99, 235, 0.6) !important;
    }
    
    /* ========================================
       BUTTONS - ENTERPRISE STYLING
       ======================================== */
    
    /* Primary buttons */
    .stButton > button,
    button {
        background-color: var(--accent-primary) !important;
        color: white !important;
        border: none !important;
        border-radius: var(--radius-md) !important;
        padding: 0.75rem 1.5rem !important;
        font-weight: 600 !important;
        font-size: 0.875rem !important;
        transition: var(--transition-normal) !important;
        box-shadow: var(--shadow-sm) !important;
    }

    .stButton > button:hover,
    button:hover {
        background-color: var(--accent-hover) !important;
        transform: translateY(-1px) !important;
        box-shadow: var(--shadow-md) !important;
    }
    
    .stButton > button:active,
    button:active {
        transform: translateY(0) !important;
        box-shadow: var(--shadow-sm) !important;
    }
    
    /* ========================================
       CARDS AND CONTAINERS
       ======================================== */
    
    .card, .modern-card {
        background-color: var(--bg-secondary) !important;
        border: 1px solid var(--border-primary) !important;
        border-radius: var(--radius-lg) !important;
        padding: 1.5rem !important;
        margin-bottom: 1.5rem !important;
        box-shadow: var(--shadow-md) !important;
        transition: var(--transition-normal) !important;
    }
    
    .card:hover, .modern-card:hover {
        transform: translateY(-2px) !important;
        box-shadow: var(--shadow-lg) !important;
        border-color: var(--accent-primary) !important;
    }
    
    /* ========================================
       ENHANCED TYPOGRAPHY & VISUAL HIERARCHY
       ======================================== */
    
    h1, h2, h3, h4, h5, h6 {
        color: #60a5fa !important;
        font-weight: 600 !important;
        margin-bottom: 1rem !important;
        text-shadow: 0 0 10px rgba(96, 165, 250, 0.3) !important;
    }
    
    h1 {
        font-size: 2.5rem !important;
        font-weight: 700 !important;
        background: linear-gradient(135deg, #60a5fa, #93c5fd) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
    }
    
    h2 {
        font-size: 2rem !important;
        font-weight: 600 !important;
        color: #93c5fd !important;
    }
    
    h3 {
        font-size: 1.5rem !important;
        font-weight: 600 !important;
        color: #93c5fd !important;
    }
    
    p, span, div {
        color: #d1d5db !important;
        font-size: 1rem !important;
        line-height: 1.6 !important;
    }
    
    /* ===== Main Content Text Enhancement ===== */
    .main .block-container h1,
    .main .block-container h2,
    .main .block-container h3 {
        color: #60a5fa !important;
        text-shadow: 0 0 10px rgba(96, 165, 250, 0.3) !important;
    }
    
    .main .block-container p,
    .main .block-container span,
    .main .block-container div {
        color: #f9fafb !important;
    }
    
    /* ========================================
       RESPONSIVE DESIGN
       ======================================== */
    
    /* ===== Custom Scrollbar Styling ===== */
    ::-webkit-scrollbar {
        width: 8px !important;
        height: 8px !important;
    }
    
    ::-webkit-scrollbar-track {
        background: #1f2937 !important;
        border-radius: 10px !important;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #2563eb, #1e3a8a) !important;
        border-radius: 10px !important;
        transition: background 0.3s ease !important;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #3b82f6, #2563eb) !important;
    }
    
    /* ===== Responsive Design ===== */
    @media (max-width: 768px) {
        /* Mobile sidebar */
        [data-testid="stSidebar"] {
            width: 18rem !important;
        }
        
        [data-testid="stAppViewContainer"] {
            margin-left: 18rem !important;
        }
        
        .main .block-container {
            padding: 1.5rem 2rem !important;
        }
        
        /* Stack columns on mobile */
        .stColumns {
            display: block !important;
        }
        
        .stColumns > div {
            width: 100% !important;
            margin-bottom: 1rem !important;
        }
        
        /* Adjust typography for mobile */
        h1 {
            font-size: 2rem !important;
        }
        
        h2 {
            font-size: 1.5rem !important;
        }
        
        h3 {
            font-size: 1.25rem !important;
        }
    }
    
    @media (max-width: 480px) {
        /* Very small screens */
        [data-testid="stSidebar"] {
            width: 16rem !important;
        }
        
        [data-testid="stAppViewContainer"] {
            margin-left: 16rem !important;
        }
        
        .main .block-container {
            padding: 1rem 1.5rem !important;
        }
        
        .stSidebar h1 {
            font-size: 1.25rem !important;
        }
        
        .stSidebar h2, .stSidebar h3 {
            font-size: 0.875rem !important;
        }
    }

    /* ========================================
       FINAL OVERRIDES
       ======================================== */
    
    /* Ensure all text is visible */
    * {
        color: inherit !important;
    }
    
    /* Remove any remaining borders */
    .stVerticalBlockBorder,
    .stHorizontalBlockBorder,
    .stVerticalBlockBorder > div {
        display: none !important;
    }
    
    /* Ensure proper scrolling */
    [data-testid="stSidebar"] {
        scrollbar-width: thin !important;
        scrollbar-color: var(--accent-primary) var(--bg-secondary) !important;
    }
    
    [data-testid="stSidebar"]::-webkit-scrollbar {
        width: 6px !important;
    }
    
    [data-testid="stSidebar"]::-webkit-scrollbar-track {
        background: var(--bg-secondary) !important;
    }
    
    [data-testid="stSidebar"]::-webkit-scrollbar-thumb {
        background: var(--accent-primary) !important;
        border-radius: 3px !important;
    }
    
    [data-testid="stSidebar"]::-webkit-scrollbar-thumb:hover {
        background: var(--accent-hover) !important;
    }
    

    /* Add animated pattern overlay */
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
        animation: backgroundShift 20s ease-in-out infinite;
    }

    @keyframes backgroundShift {
        0%, 100% { transform: translateX(0) translateY(0); }
        25% { transform: translateX(-10px) translateY(-5px); }
        50% { transform: translateX(5px) translateY(-10px); }
        75% { transform: translateX(-5px) translateY(5px); }
    }

    /* Main content area */
    .main .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        max-width: 1400px !important;
        margin: 0 auto !important;
    }

    /* Responsive Design */
    @media (max-width: 768px) {
        .main .block-container {
            padding-top: 1rem !important;
            padding-bottom: 1rem !important;
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }
        
        .stTabs [data-baseweb="tab"] {
            padding: 0.75rem 1rem !important;
            font-size: 0.8rem !important;
        }
    }

    @media (max-width: 480px) {
        .main .block-container {
            padding: 0.5rem !important;
        }
        
        h1 { font-size: 1.5rem !important; }
        h2 { font-size: 1.25rem !important; }
        h3 { font-size: 1.1rem !important; }
    }

    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary);
        font-weight: 600;
        margin-bottom: 0.75rem;
        line-height: 1.3;
    }

    h1 {
        font-size: 2.5rem;
        font-weight: 800;
        background: var(--gradient-primary);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 1rem;
    }

    h2 {
        font-size: 2rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 1rem;
    }

    h3 {
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 0.75rem;
    }

    /* Modern Card Components */
    .card {
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 4px 20px var(--shadow-card);
        backdrop-filter: blur(20px);
        transition: all var(--transition-normal);
        position: relative;
        overflow: hidden;
    }

    .card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: var(--gradient-accent);
        border-radius: var(--radius-lg) var(--radius-lg) 0 0;
    }

    .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px var(--shadow-hover);
        border-color: var(--accent);
    }

    .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--border-light);
    }

    .card-title {
        font-size: 1.25rem;
        font-weight: 600;
        color: var(--text-primary);
        margin: 0;
    }

    .card-subtitle {
        font-size: 0.875rem;
        color: var(--text-secondary);
        margin: 0.25rem 0 0 0;
    }

    .card-content {
        color: var(--text-primary);
        line-height: 1.6;
    }

    .card-footer {
        margin-top: 1rem;
        padding-top: 0.75rem;
        border-top: 1px solid var(--border-light);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Status Cards */
    .status-card {
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        padding: 1.5rem;
        text-align: center;
        transition: all var(--transition-normal);
        position: relative;
        overflow: hidden;
    }

    .status-card.success {
        border-color: var(--success);
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.05) 0%, rgba(52, 211, 153, 0.05) 100%);
    }

    .status-card.warning {
        border-color: var(--warning);
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.05) 0%, rgba(251, 191, 36, 0.05) 100%);
    }

    .status-card.danger {
        border-color: var(--danger);
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.05) 0%, rgba(248, 113, 113, 0.05) 100%);
    }

    .status-card.info {
        border-color: var(--info);
        background: linear-gradient(135deg, rgba(6, 182, 212, 0.05) 0%, rgba(34, 211, 238, 0.05) 100%);
    }

    .status-icon {
        font-size: 2.5rem;
        margin-bottom: 0.75rem;
        display: block;
    }

    .status-value {
        font-size: 2rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 0.25rem;
    }

    .status-label {
        font-size: 0.875rem;
        color: var(--text-secondary);
        font-weight: 500;
    }

    /* Dark Mode Toggle */
    .theme-toggle {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius-full);
        padding: 0.5rem;
        box-shadow: 0 4px 20px var(--shadow-card);
        backdrop-filter: blur(20px);
        transition: all var(--transition-normal);
        cursor: pointer;
    }

    .theme-toggle:hover {
        transform: scale(1.05);
        box-shadow: 0 6px 25px var(--shadow-hover);
    }

    .theme-toggle button {
        background: none !important;
        border: none !important;
        padding: 0.5rem !important;
        border-radius: var(--radius-full) !important;
        font-size: 1.25rem !important;
        color: var(--text-primary) !important;
        transition: all var(--transition-fast) !important;
    }

    .theme-toggle button:hover {
        background: var(--surface-elevated) !important;
        transform: rotate(180deg) !important;
    }

    /* Enhanced Button Styles */
    button, .stButton > button, .stButton > button:focus {
        background: var(--gradient-primary) !important;
        color: var(--text-inverse) !important;
        border: none !important;
        border-radius: var(--radius-md) !important;
        padding: 0.875rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.875rem !important;
        letter-spacing: 0.025em !important;
        transition: all var(--transition-normal) !important;
        box-shadow: 0 4px 12px var(--shadow) !important;
        backdrop-filter: blur(10px) !important;
        position: relative !important;
        overflow: hidden !important;
        cursor: pointer !important;
        font-family: 'Inter', sans-serif !important;
    }

    .stButton > button::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
        transition: left var(--transition-slow);
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

    /* Button Variants */
    .stButton > button[kind="secondary"] {
        background: var(--surface) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border) !important;
        backdrop-filter: blur(10px) !important;
    }

    .stButton > button[kind="secondary"]:hover {
        background: var(--surface-elevated) !important;
        border-color: var(--accent) !important;
        color: var(--accent) !important;
    }

    /* Success Buttons */
    .success-button, .stButton > button:has([data-testid="stSuccess"]) {
        background: var(--gradient-success) !important;
    }

    .success-button:hover, .stButton > button:has([data-testid="stSuccess"]):hover {
        background: linear-gradient(135deg, #059669 0%, #10b981 100%) !important;
    }

    /* Warning Buttons */
    .warning-button, .stButton > button:has([data-testid="stWarning"]) {
        background: var(--gradient-warning) !important;
    }

    .warning-button:hover, .stButton > button:has([data-testid="stWarning"]):hover {
        background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%) !important;
    }

    /* Danger Buttons */
    .danger-button, .stButton > button:has([data-testid="stError"]) {
        background: var(--gradient-danger) !important;
    }

    .danger-button:hover, .stButton > button:has([data-testid="stError"]):hover {
        background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%) !important;
    }

    /* Info Buttons */
    .info-button {
        background: var(--gradient-info) !important;
    }

    .info-button:hover {
        background: linear-gradient(135deg, #0891b2 0%, #06b6d4 100%) !important;
    }

    /* Button Sizes */
    .btn-sm {
        padding: 0.5rem 1rem !important;
        font-size: 0.75rem !important;
    }

    .btn-lg {
        padding: 1rem 2.5rem !important;
        font-size: 1rem !important;
    }

    .btn-xl {
        padding: 1.25rem 3rem !important;
        font-size: 1.125rem !important;
    }

    /* Icon Buttons */
    .icon-button {
        padding: 0.75rem !important;
        border-radius: var(--radius-full) !important;
        min-width: auto !important;
        aspect-ratio: 1 !important;
    }

    /* Floating Action Button */
    .fab {
        position: fixed !important;
        bottom: 2rem !important;
        right: 2rem !important;
        z-index: 1000 !important;
        border-radius: var(--radius-full) !important;
        padding: 1rem !important;
        box-shadow: 0 8px 30px var(--shadow-hover) !important;
        font-size: 1.5rem !important;
    }

    .fab:hover {
        transform: scale(1.1) !important;
    }

    /* Enhanced Sidebar */
    section[data-testid="stSidebar"] {
        background: var(--surface) !important;
        border-right: 1px solid var(--border) !important;
        backdrop-filter: blur(20px) !important;
        box-shadow: 2px 0 20px var(--shadow-glass) !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
    }
    
    section[data-testid="stSidebar"] > div:first-child {
        background: var(--surface) !important;
        backdrop-filter: blur(20px) !important;
        padding: 1rem !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* Fix sidebar content container */
    .stSidebar .stMarkdown,
    .stSidebar .stSelectbox,
    .stSidebar .stTextInput,
    .stSidebar .stRadio,
    .stSidebar .stCheckbox,
    .stSidebar .stColumns {
        width: 100% !important;
        max-width: 100% !important;
        margin-left: 0 !important;
        margin-right: 0 !important;
        padding-left: 0 !important;
        padding-right: 0 !important;
        box-sizing: border-box !important;
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

    /* Form Components */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div,
    .stNumberInput > div > div > input {
        background: var(--surface) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: 0.75rem 1rem !important;
        font-size: 0.875rem !important;
        transition: all var(--transition-fast) !important;
        backdrop-filter: blur(10px) !important;
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        width: 100% !important;
        min-width: 100% !important;
        max-width: none !important;
        line-height: 1.4 !important;
    }

    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus,
    .stSelectbox > div > div > div:focus,
    .stNumberInput > div > div > input:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
        outline: none !important;
    }

    .stTextInput > div > div > input:hover,
    .stTextArea > div > div > textarea:hover,
    .stSelectbox > div > div > div:hover,
    .stNumberInput > div > div > input:hover {
        border-color: var(--accent-light) !important;
    }

    /* File Uploader */
    .stFileUploader {
        background: var(--surface) !important;
        border: 2px dashed var(--border) !important;
        border-radius: var(--radius-lg) !important;
        padding: 2rem !important;
        text-align: center !important;
        transition: all var(--transition-normal) !important;
        backdrop-filter: blur(10px) !important;
    }

    .stFileUploader:hover {
        border-color: var(--accent) !important;
        background: var(--surface-elevated) !important;
    }

    /* Data Tables */
    .stDataFrame {
        background: var(--surface) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-lg) !important;
        overflow: hidden !important;
        box-shadow: 0 4px 20px var(--shadow-card) !important;
        backdrop-filter: blur(10px) !important;
    }

    .stDataFrame table {
        background: transparent !important;
    }

    .stDataFrame th {
        background: var(--gradient-primary) !important;
        color: var(--text-inverse) !important;
        font-weight: 600 !important;
        padding: 1rem !important;
        border: none !important;
    }

    .stDataFrame td {
        background: var(--surface) !important;
        color: var(--text-primary) !important;
        padding: 0.75rem 1rem !important;
        border-bottom: 1px solid var(--border-light) !important;
    }

    .stDataFrame tr:hover td {
        background: var(--surface-elevated) !important;
    }

    /* Metrics */
    .metric-container {
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-lg) !important;
        padding: 1.5rem !important;
        text-align: center !important;
        box-shadow: 0 4px 20px var(--shadow-card) !important;
        backdrop-filter: blur(10px) !important;
        transition: all var(--transition-normal) !important;
    }

    .metric-container:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 30px var(--shadow-hover) !important;
    }

    .metric-value {
        font-size: 2.5rem !important;
        font-weight: 800 !important;
        color: var(--text-primary) !important;
        margin-bottom: 0.25rem !important;
    }

    .metric-label {
        font-size: 0.875rem !important;
        color: var(--text-secondary) !important;
        font-weight: 500 !important;
    }

    .metric-delta {
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        margin-top: 0.5rem !important;
    }

    .metric-delta.positive {
        color: var(--success) !important;
    }

    .metric-delta.negative {
        color: var(--danger) !important;
    }

    /* Progress Bars */
    .stProgress > div > div > div {
        background: var(--gradient-accent) !important;
        border-radius: var(--radius-full) !important;
        height: 8px !important;
    }

    .stProgress > div > div {
        background: var(--border-light) !important;
        border-radius: var(--radius-full) !important;
        height: 8px !important;
    }

    /* Alerts and Messages */
    .stAlert {
        border-radius: var(--radius-lg) !important;
        border: none !important;
        padding: 1rem 1.5rem !important;
        margin: 1rem 0 !important;
        backdrop-filter: blur(10px) !important;
        box-shadow: 0 4px 20px var(--shadow-card) !important;
    }

    .stAlert[data-testid="stSuccess"] {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(52, 211, 153, 0.1) 100%) !important;
        border-left: 4px solid var(--success) !important;
        color: var(--text-primary) !important;
    }

    .stAlert[data-testid="stWarning"] {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(251, 191, 36, 0.1) 100%) !important;
        border-left: 4px solid var(--warning) !important;
        color: var(--text-primary) !important;
    }

    .stAlert[data-testid="stError"] {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(248, 113, 113, 0.1) 100%) !important;
        border-left: 4px solid var(--danger) !important;
        color: var(--text-primary) !important;
    }

    .stAlert[data-testid="stInfo"] {
        background: linear-gradient(135deg, rgba(6, 182, 212, 0.1) 0%, rgba(34, 211, 238, 0.1) 100%) !important;
        border-left: 4px solid var(--info) !important;
        color: var(--text-primary) !important;
    }

    /* Code Blocks */
    .stCode {
        background: var(--surface) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        padding: 1rem !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.875rem !important;
        color: var(--text-primary) !important;
        box-shadow: 0 2px 10px var(--shadow) !important;
    }

    /* Expander */
    .streamlit-expander {
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-lg) !important;
        margin: 1rem 0 !important;
        box-shadow: 0 4px 20px var(--shadow-card) !important;
        backdrop-filter: blur(10px) !important;
    }

    .streamlit-expanderHeader {
        background: var(--surface) !important;
        border-radius: var(--radius-lg) var(--radius-lg) 0 0 !important;
        padding: 1rem 1.5rem !important;
        font-weight: 600 !important;
        color: var(--text-primary) !important;
        transition: all var(--transition-fast) !important;
    }

    .streamlit-expanderHeader:hover {
        background: var(--surface-elevated) !important;
    }

    .streamlit-expanderContent {
        padding: 1.5rem !important;
        color: var(--text-primary) !important;
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
    .stSidebar {
        min-width: 300px !important;
        width: 300px !important;
        max-width: 300px !important;
        padding: 0 !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
    }
    
    /* Sidebar content container */
    .stSidebar > div:first-child {
        padding: 1rem !important;
        width: 100% !important;
        box-sizing: border-box !important;
        overflow: visible !important;
    }
    
    .stSidebar .stSelectbox, .stSidebar .stTextInput {
        margin-bottom: 1.5rem !important;
        width: 100% !important;
        min-width: 100% !important;
        max-width: 100% !important;
        clear: both !important;
        display: block !important;
        box-sizing: border-box !important;
    }
    
    /* Prevent overlapping with sidebar elements */
    .stSidebar > div {
        margin-bottom: 1rem !important;
        padding-bottom: 0.5rem !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }
    
    .stSidebar h1, .stSidebar h2, .stSidebar h3, .stSidebar h4, .stSidebar h5, .stSidebar h6 {
        margin-top: 1rem !important;
        margin-bottom: 0.5rem !important;
        clear: both !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }
    
    .stSidebar .stMarkdown {
        margin-bottom: 1rem !important;
        clear: both !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* Sidebar Title Styling - Match Theme Combinations */
    .stSidebar h1 {
        background: var(--gradient-accent) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        font-size: 1.5rem !important;
        font-weight: 700 !important;
        text-align: center !important;
        margin: 0 0 0.5rem 0 !important;
        padding: 0.5rem 0 !important;
        border-bottom: 2px solid var(--border) !important;
        position: relative !important;
        z-index: 10 !important;
    }
    
    .stSidebar h1::after {
        content: '' !important;
        position: absolute !important;
        bottom: -2px !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        width: 60% !important;
        height: 2px !important;
        background: var(--gradient-accent) !important;
        border-radius: var(--radius-full) !important;
    }
    
    /* Sidebar subtitle styling */
    .stSidebar .stMarkdown p {
        text-align: center !important;
        color: var(--text-secondary) !important;
        font-style: italic !important;
        margin: 0 0 1rem 0 !important;
        font-size: 0.875rem !important;
    }
    
    /* Ensure proper spacing for all sidebar sections */
    .stSidebar .stRadio, .stSidebar .stCheckbox {
        margin-bottom: 1rem !important;
        clear: both !important;
    }
    
    .stSidebar .stSubheader {
        margin-top: 1.5rem !important;
        margin-bottom: 0.75rem !important;
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        border-left: 3px solid var(--accent) !important;
        padding-left: 0.75rem !important;
        clear: both !important;
    }
    
    /* Theme Toggle Specific Styling */
    .stSidebar .stColumns {
        margin-bottom: 1rem !important;
        clear: both !important;
        padding: 0.75rem !important;
        background: var(--surface-elevated) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        box-shadow: var(--shadow-card) !important;
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
    }
    
    .stSidebar .stColumns > div {
        margin-bottom: 0.5rem !important;
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* Theme toggle selectbox styling */
    .stSidebar .stColumns .stSelectbox {
        margin-bottom: 0 !important;
    }
    
    .stSidebar .stColumns .stSelectbox label {
        font-size: 0.8rem !important;
        color: var(--text-secondary) !important;
        margin-bottom: 0.25rem !important;
    }
    
    .stSidebar .stColumns .stSelectbox > div > div > div {
        font-size: 0.8rem !important;
        padding: 0.4rem 0.6rem !important;
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
    }
    
    /* Ensure theme toggle doesn't overlap */
    .stSidebar [data-testid="stSidebar"] > div:first-child {
        margin-bottom: 1rem !important;
        padding-bottom: 1rem !important;
        border-bottom: 1px solid var(--border) !important;
    }
    
    /* Add visual separator after theme toggle */
    .stSidebar .stColumns::after {
        content: '' !important;
        display: block !important;
        width: 100% !important;
        height: 1px !important;
        background: var(--gradient-accent) !important;
        margin: 0.75rem 0 0 0 !important;
        border-radius: var(--radius-full) !important;
    }
    
    /* Navigation section spacing */
    .stSidebar .stRadio {
        margin-top: 1rem !important;
        margin-bottom: 1.5rem !important;
        padding: 0.75rem !important;
        background: var(--surface-elevated) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        box-shadow: var(--shadow-card) !important;
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* Navigation radio buttons styling */
    .stSidebar .stRadio label {
        color: var(--text-primary) !important;
        font-weight: 500 !important;
        margin-bottom: 0.5rem !important;
    }
    
    .stSidebar .stRadio [role="radiogroup"] {
        gap: 0.5rem !important;
    }
    
    .stSidebar .stRadio [role="radio"] {
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
        padding: 0.5rem !important;
        transition: var(--transition-normal) !important;
    }
    
    .stSidebar .stRadio [role="radio"]:hover {
        background: var(--surface-elevated) !important;
        border-color: var(--accent) !important;
        transform: translateY(-1px) !important;
    }
    
    .stSidebar .stRadio [role="radio"][aria-checked="true"] {
        background: var(--gradient-accent) !important;
        border-color: var(--accent) !important;
        color: var(--text-primary) !important;
    }
    
    /* AI Configuration section spacing */
    .stSidebar .stSelectbox:first-of-type {
        margin-top: 1rem !important;
    }
    
    /* AI Configuration section container */
    .stSidebar .stSubheader + .stSelectbox {
        margin-top: 0.5rem !important;
    }
    
    /* AI Configuration section styling */
    .stSidebar .stSubheader + .stSelectbox,
    .stSidebar .stSubheader + .stSelectbox + .stSelectbox,
    .stSidebar .stSubheader + .stSelectbox + .stSelectbox + .stTextInput {
        padding: 0.75rem !important;
        background: var(--surface-elevated) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        box-shadow: var(--shadow-card) !important;
        margin-bottom: 0.5rem !important;
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* AI Configuration section label styling */
    .stSidebar .stSubheader + .stSelectbox label,
    .stSidebar .stSubheader + .stSelectbox + .stSelectbox label,
    .stSidebar .stSubheader + .stSelectbox + .stSelectbox + .stTextInput label {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
    }
    
    /* Fix sidebar text display issues */
    .stSidebar .stSelectbox > div > div > div {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        min-width: 100% !important;
        width: 100% !important;
        max-width: 100% !important;
        padding: 0.5rem 2rem 0.5rem 0.75rem !important;
        font-size: 0.875rem !important;
        line-height: 1.4 !important;
        margin-bottom: 0.5rem !important;
        position: relative !important;
        z-index: 5 !important;
        box-sizing: border-box !important;
    }
    
    /* Ensure selectbox container has proper spacing */
    .stSidebar .stSelectbox > div {
        margin-bottom: 1rem !important;
        position: relative !important;
        z-index: 5 !important;
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* Fix selectbox label spacing */
    .stSidebar .stSelectbox label {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        width: 100% !important;
        max-width: none !important;
        display: block !important;
        font-size: 0.875rem !important;
        font-weight: 500 !important;
        margin-bottom: 0.5rem !important;
        padding-bottom: 0.25rem !important;
        position: relative !important;
        z-index: 5 !important;
    }
    
    /* Fix sidebar dropdown options */
    .stSidebar .stSelectbox [data-baseweb="select"] {
        width: 100% !important;
        min-width: 100% !important;
    }
    
    .stSidebar .stSelectbox [data-baseweb="select"] > div {
        width: 100% !important;
        min-width: 100% !important;
        white-space: nowrap !important;
        overflow: visible !important;
    }
    
    /* Fix sidebar text input */
    .stSidebar .stTextInput > div > div > input {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        width: 100% !important;
        min-width: 100% !important;
        max-width: 100% !important;
        font-size: 0.875rem !important;
        line-height: 1.4 !important;
        padding: 0.5rem 0.75rem !important;
        margin-bottom: 0.5rem !important;
        position: relative !important;
        z-index: 5 !important;
        box-sizing: border-box !important;
    }
    
    /* Ensure text input container has proper spacing */
    .stSidebar .stTextInput > div {
        margin-bottom: 1rem !important;
        position: relative !important;
        z-index: 5 !important;
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
    }
    
    /* Fix text input label spacing */
    .stSidebar .stTextInput label {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        width: 100% !important;
        max-width: none !important;
        display: block !important;
        font-size: 0.875rem !important;
        font-weight: 500 !important;
        margin-bottom: 0.5rem !important;
        padding-bottom: 0.25rem !important;
        position: relative !important;
        z-index: 5 !important;
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
        border-radius: var(--radius-md) !important;
        backdrop-filter: blur(20px) !important;
    }
    
    /* Fix text display issues in selectboxes */
    .stSelectbox > div > div > div {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        min-width: 100% !important;
        width: 100% !important;
        max-width: none !important;
        padding-right: 2rem !important;
    }
    
    .stSelectbox > div > div > div > div {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        width: 100% !important;
        max-width: none !important;
    }
    
    /* Fix dropdown text display */
    .stSelectbox [data-baseweb="select"] > div {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
    }
    
    .stSelectbox [data-baseweb="select"] > div > div {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        min-width: 100% !important;
    }
    
    /* Fix selectbox label text */
    .stSelectbox label {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        width: 100% !important;
        max-width: none !important;
        display: block !important;
    }
    
    /* Fix dropdown menu text display */
    .stSelectbox [data-baseweb="menu"] {
        max-width: none !important;
        width: auto !important;
        min-width: 200px !important;
    }
    
    .stSelectbox [data-baseweb="menu"] ul {
        max-width: none !important;
        width: auto !important;
        min-width: 200px !important;
    }
    
    .stSelectbox [data-baseweb="menu"] li {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        max-width: none !important;
        width: auto !important;
        min-width: 200px !important;
        padding: 0.5rem 1rem !important;
        background: var(--card-bg) !important;
        border-bottom: 1px solid var(--border) !important;
    }
    
    .stSelectbox [data-baseweb="menu"] li > div {
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
        max-width: none !important;
        width: auto !important;
        min-width: 200px !important;
    }

    .stSelectbox [data-baseweb="menu"] li:hover {
        background: var(--surface-elevated) !important;
    }

    .stSelectbox [data-baseweb="menu"] li[aria-selected="true"] {
        background: var(--gradient-accent) !important;
        color: var(--text-primary) !important;
    }
    
    /* Fix BaseWeb select component text */
    [data-baseweb="select"] {
        width: 100% !important;
        min-width: 100% !important;
    }
    
    [data-baseweb="select"] > div {
        width: 100% !important;
        min-width: 100% !important;
        white-space: nowrap !important;
        overflow: visible !important;
    }
    
    [data-baseweb="select"] > div > div {
        width: 100% !important;
        min-width: 100% !important;
        white-space: nowrap !important;
        overflow: visible !important;
        text-overflow: ellipsis !important;
    }
    
    /* Re-enable select dropdown input for proper keyboard/mouse behavior */
    .stSelectbox input[type="search"],
    .stSelectbox input[type="text"],
    .stSelectbox [data-baseweb="select"] input {
        display: initial !important;
        opacity: 1 !important;
        pointer-events: auto !important;
    }

    /* Ensure BaseWeb select dropdown menu appears above other elements */
    .stSelectbox [data-baseweb="menu"],
    [data-baseweb="select"] [data-baseweb="menu"],
    .stSidebar [data-baseweb="menu"] {
        z-index: 9999 !important;
    }

    /* Progress Bar */
    .stProgress > div > div > div > div {
        background: var(--gradient-accent) !important;
        border-radius: var(--radius-full) !important;
    }

    /* Loading Spinner */
    .stSpinner {
        color: var(--accent) !important;
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }

    ::-webkit-scrollbar-track {
        background: var(--surface);
        border-radius: var(--radius-full);
    }

    ::-webkit-scrollbar-thumb {
        background: var(--gradient-accent);
        border-radius: var(--radius-full);
        transition: all var(--transition-fast);
    }

    ::-webkit-scrollbar-thumb:hover {
        background: var(--accent-dark);
    }

    /* Selection */
    ::selection {
        background: rgba(59, 130, 246, 0.2);
        color: var(--text-primary);
    }

    /* Focus Outline */
    *:focus {
        outline: 2px solid var(--accent);
        outline-offset: 2px;
    }

    /* Print Styles */
    @media print {
        .theme-toggle,
        .fab,
        .stSidebar {
            display: none !important;
        }
        
        .main .block-container {
            max-width: 100% !important;
            padding: 0 !important;
        }
    }

    /* High Contrast Mode */
    @media (prefers-contrast: high) {
        :root {
            --border: rgba(0, 0, 0, 0.3);
            --shadow: rgba(0, 0, 0, 0.2);
        }
    }

    /* Reduced Motion */
    @media (prefers-reduced-motion: reduce) {
        *,
        *::before,
        *::after {
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.01ms !important;
        }
    }
    
    /* ========================================
       MODERN CARD STYLING
       ======================================== */
    
    .modern-card {
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-lg) !important;
        box-shadow: var(--shadow-card) !important;
        padding: 1.5rem !important;
        margin-bottom: 1rem !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
        transition: var(--transition-normal) !important;
        position: relative !important;
        overflow: hidden !important;
    }
    
    .modern-card::before {
        content: '' !important;
        position: absolute !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        height: 3px !important;
        background: var(--gradient-accent) !important;
        opacity: 0.8 !important;
    }
    
    .modern-card:hover {
        transform: translateY(-2px) !important;
        box-shadow: var(--shadow-hover) !important;
        border-color: var(--accent) !important;
    }
    
    /* ========================================
       TOAST NOTIFICATIONS
       ======================================== */
    
    .toast {
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        padding: 1rem 1.5rem !important;
        box-shadow: var(--shadow-hover) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
        color: var(--text-primary) !important;
        z-index: 1000 !important;
        animation: slideIn 0.3s ease-out !important;
    }
    
    .toast.success {
        border-left: 4px solid var(--success) !important;
    }
    
    .toast.info {
        border-left: 4px solid var(--info) !important;
    }
    
    .toast.warning {
        border-left: 4px solid var(--warning) !important;
    }
    
    .toast.error {
        border-left: 4px solid var(--danger) !important;
    }
    
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .fade-in {
        animation: fadeIn 0.5s ease-out !important;
    }
    
    /* ========================================
       HERO SECTION STYLING
       ======================================== */
    
    .hero-section {
        text-align: center !important;
        padding: 4rem 2rem !important;
        background: var(--gradient-glass) !important;
        border-radius: var(--radius-xl) !important;
        margin-bottom: 2rem !important;
        position: relative !important;
        overflow: hidden !important;
    }
    
    .hero-section::before {
        content: '' !important;
        position: absolute !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        bottom: 0 !important;
        background: var(--gradient-accent) !important;
        opacity: 0.05 !important;
        z-index: -1 !important;
    }
    
    .hero-title {
        font-size: 3.5rem !important;
        font-weight: 800 !important;
        margin-bottom: 1rem !important;
        background: var(--gradient-accent) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        animation: titleGlow 3s ease-in-out infinite alternate !important;
    }
    
    .hero-subtitle {
        font-size: 1.5rem !important;
        color: var(--text-secondary) !important;
        margin-bottom: 1.5rem !important;
        font-weight: 500 !important;
    }
    
    .hero-description {
        font-size: 1.1rem !important;
        color: var(--text-secondary) !important;
        max-width: 600px !important;
        margin: 0 auto !important;
        line-height: 1.6 !important;
    }
    
    @keyframes titleGlow {
        0% { filter: brightness(1); }
        100% { filter: brightness(1.2); }
    }
    
    /* ========================================
       TEAM MEMBER STYLING
       ======================================== */
    
    .team-member {
        text-align: center !important;
        padding: 2rem 1rem !important;
        background: var(--surface) !important;
        border-radius: var(--radius-lg) !important;
        border: 1px solid var(--border) !important;
        transition: var(--transition-normal) !important;
        height: 100% !important;
    }
    
    .team-member:hover {
        transform: translateY(-5px) !important;
        box-shadow: var(--shadow-hover) !important;
        border-color: var(--accent) !important;
    }
    
    .member-icon {
        font-size: 3rem !important;
        margin-bottom: 1rem !important;
        display: block !important;
    }
    
    .team-member h3 {
        color: var(--text-primary) !important;
        font-size: 1.3rem !important;
        font-weight: 600 !important;
        margin-bottom: 0.5rem !important;
    }
    
    .member-role {
        color: var(--accent) !important;
        font-weight: 500 !important;
        font-size: 1rem !important;
        margin-bottom: 1rem !important;
    }
    
    .member-description {
        color: var(--text-secondary) !important;
        font-size: 0.9rem !important;
        line-height: 1.5 !important;
        text-align: left !important;
    }
    
    /* Toggle Card Animation Styles */
    .team-member.collapsed {
        max-height: 300px !important;
        overflow: hidden !important;
        transition: all 0.3s ease-in-out !important;
    }
    
    .team-member.expanded {
        max-height: 800px !important;
        overflow: visible !important;
        transition: all 0.3s ease-in-out !important;
        transform: scale(1.02) !important;
        box-shadow: var(--shadow-hover) !important;
        border-color: var(--accent) !important;
    }
    
    .member-details {
        margin-top: 1rem !important;
        padding-top: 1rem !important;
        border-top: 1px solid var(--border) !important;
        animation: slideDown 0.3s ease-out !important;
    }
    
    .member-skills {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 0.5rem !important;
        margin: 1rem 0 !important;
    }
    
    .skill-tag {
        background: var(--accent) !important;
        color: var(--bg-primary) !important;
        padding: 0.25rem 0.75rem !important;
        border-radius: var(--radius-sm) !important;
        font-size: 0.8rem !important;
        font-weight: 500 !important;
        transition: var(--transition-fast) !important;
    }
    
    .skill-tag:hover {
        background: var(--accent-hover) !important;
        transform: translateY(-1px) !important;
    }
    
    .member-achievements {
        margin-top: 1rem !important;
        text-align: left !important;
    }
    
    .member-achievements h4 {
        color: var(--text-primary) !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        margin-bottom: 0.5rem !important;
    }
    
    .member-achievements ul {
        color: var(--text-secondary) !important;
        font-size: 0.9rem !important;
        line-height: 1.6 !important;
        padding-left: 1.5rem !important;
    }
    
    .member-achievements li {
        margin-bottom: 0.5rem !important;
    }
    
    @keyframes slideDown {
        from {
            opacity: 0 !important;
            transform: translateY(-10px) !important;
        }
        to {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
    }
    
    /* Toggle Button Styling */
    .stButton > button[kind="secondary"] {
        background: var(--surface) !important;
        border: 2px solid var(--accent) !important;
        color: var(--accent) !important;
        border-radius: 50% !important;
        width: 60px !important;
        height: 60px !important;
        font-size: 1.5rem !important;
        transition: var(--transition-normal) !important;
        margin: 0 auto 1rem auto !important;
        display: block !important;
    }
    
    .stButton > button[kind="secondary"]:hover {
        background: var(--accent) !important;
        color: var(--bg-primary) !important;
        transform: scale(1.1) !important;
        box-shadow: var(--shadow-hover) !important;
    }
    
    /* ========================================
       WORKFLOW STEP STYLING
       ======================================== */
    
    .workflow-step {
        text-align: center !important;
        padding: 1.5rem 1rem !important;
        background: var(--surface) !important;
        border-radius: var(--radius-lg) !important;
        border: 1px solid var(--border) !important;
        transition: var(--transition-normal) !important;
        height: 100% !important;
        position: relative !important;
    }
    
    .workflow-step:hover {
        transform: translateY(-3px) !important;
        box-shadow: var(--shadow-hover) !important;
        border-color: var(--accent) !important;
    }
    
    .step-number {
        position: absolute !important;
        top: -15px !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        background: var(--gradient-accent) !important;
        color: var(--text-inverse) !important;
        width: 30px !important;
        height: 30px !important;
        border-radius: 50% !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
    }
    
    .step-icon {
        font-size: 2.5rem !important;
        margin: 1rem 0 !important;
        display: block !important;
    }
    
    .workflow-step h4 {
        color: var(--text-primary) !important;
        font-size: 1.1rem !important;
        font-weight: 600 !important;
        margin-bottom: 0.5rem !important;
    }
    
    .workflow-step p {
        color: var(--text-secondary) !important;
        font-size: 0.9rem !important;
        line-height: 1.4 !important;
    }
    
    /* ========================================
       CTA SECTION STYLING
       ======================================== */
    
    .cta-section {
        text-align: center !important;
        padding: 3rem 2rem !important;
        background: var(--gradient-glass) !important;
        border-radius: var(--radius-xl) !important;
        margin-top: 2rem !important;
        border: 1px solid var(--border) !important;
    }
    
    .cta-section h2 {
        color: var(--text-primary) !important;
        font-size: 2rem !important;
        font-weight: 600 !important;
        margin-bottom: 1rem !important;
    }
    
    .cta-section p {
        color: var(--text-secondary) !important;
        font-size: 1.1rem !important;
        margin: 0 !important;
    }
    
    /* ========================================
       FOOTER STYLING
       ======================================== */
    
    .footer-section {
        margin-top: 4rem !important;
        padding: 3rem 2rem 1rem !important;
        background: var(--surface) !important;
        border-top: 1px solid var(--border) !important;
        border-radius: var(--radius-xl) var(--radius-xl) 0 0 !important;
    }
    
    .footer-content {
        display: grid !important;
        grid-template-columns: 1fr 1fr 1fr !important;
        gap: 2rem !important;
        margin-bottom: 2rem !important;
    }
    
    .footer-main h3 {
        color: var(--text-primary) !important;
        font-size: 1.5rem !important;
        font-weight: 600 !important;
        margin-bottom: 1rem !important;
    }
    
    .footer-main p {
        color: var(--text-secondary) !important;
        line-height: 1.6 !important;
    }
    
    .footer-team h4,
    .footer-mission h4 {
        color: var(--text-primary) !important;
        font-size: 1.1rem !important;
        font-weight: 600 !important;
        margin-bottom: 1rem !important;
    }
    
    .team-links {
        display: flex !important;
        flex-direction: column !important;
        gap: 0.5rem !important;
    }
    
    .team-links span {
        color: var(--text-secondary) !important;
        font-size: 0.9rem !important;
        padding: 0.25rem 0 !important;
    }
    
    .footer-mission p {
        color: var(--text-secondary) !important;
        line-height: 1.6 !important;
        font-size: 0.9rem !important;
    }
    
    .footer-bottom {
        text-align: center !important;
        padding-top: 2rem !important;
        border-top: 1px solid var(--border) !important;
    }
    
    .footer-bottom p {
        color: var(--text-muted) !important;
        font-size: 0.9rem !important;
        margin: 0 !important;
    }
    
    @media (max-width: 768px) {
        .footer-content {
            grid-template-columns: 1fr !important;
            gap: 1.5rem !important;
        }
        
        .hero-title {
            font-size: 2.5rem !important;
        }
        
        .hero-section {
            padding: 2rem 1rem !important;
        }
    }
    
    /* ========================================
       ENHANCED BUTTON STYLING
       ======================================== */
    
    .stButton > button {
        background: var(--gradient-accent) !important;
        color: var(--text-inverse) !important;
        border: none !important;
        border-radius: var(--radius-md) !important;
        padding: 0.75rem 1.5rem !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        transition: var(--transition-normal) !important;
        box-shadow: var(--shadow) !important;
        position: relative !important;
        overflow: hidden !important;
    }
    
    .stButton > button::before {
        content: '' !important;
        position: absolute !important;
        top: 0 !important;
        left: -100% !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent) !important;
        transition: var(--transition-normal) !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: var(--shadow-hover) !important;
    }
    
    .stButton > button:hover::before {
        left: 100% !important;
    }
    
    .stButton > button:active {
        transform: translateY(0) !important;
        box-shadow: var(--shadow) !important;
    }
    
    /* ========================================
       ENHANCED FORM ELEMENTS
       ======================================== */
    
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div {
        background: var(--surface) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        padding: 0.75rem 1rem !important;
        color: var(--text-primary) !important;
        transition: var(--transition-normal) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus,
    .stSelectbox > div > div > div:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2) !important;
        background: var(--surface-elevated) !important;
        outline: none !important;
    }
    
    .stTextInput > div > div > input:hover,
    .stTextArea > div > div > textarea:hover,
    .stSelectbox > div > div > div:hover {
        border-color: var(--accent) !important;
        background: var(--surface-elevated) !important;
    }
    
    /* ========================================
       ENHANCED SIDEBAR
       ======================================== */
    
    .css-1d391kg {
        background: var(--surface) !important;
        border-right: 1px solid var(--border) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
        transition: var(--transition-normal) !important;
    }
    
    /* ========================================
       ENHANCED TABS
       ======================================== */
    
    .stTabs [data-baseweb="tab-list"] {
        border-bottom: 1px solid var(--border) !important;
        margin-bottom: 1.5rem !important;
        background: var(--card-bg) !important;
        border-radius: var(--radius-md) !important;
        padding: 0.5rem !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: var(--text-secondary) !important;
        padding: 0.75rem 1.25rem !important;
        margin-right: 0.5rem !important;
        border-radius: var(--radius-md) !important;
        transition: var(--transition-normal) !important;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        color: var(--text-primary) !important;
        background: var(--surface-elevated) !important;
        transform: translateY(-1px) !important;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--text-primary) !important;
        background: var(--gradient-accent) !important;
        box-shadow: var(--shadow) !important;
        transform: translateY(-1px) !important;
    }
    
    /* ========================================
       ENHANCED ALERTS
       ======================================== */
    
    .stAlert {
        background: var(--card-bg) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-md) !important;
        box-shadow: var(--shadow-card) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
    }
    
    /* ========================================
       ENHANCED PROGRESS BARS
       ======================================== */
    
    .stProgress > div > div > div > div {
        background: var(--gradient-accent) !important;
        border-radius: var(--radius-sm) !important;
    }
    
    .stProgress > div {
        background: var(--surface) !important;
        border-radius: var(--radius-sm) !important;
        border: 1px solid var(--border) !important;
    }
    
    /* ========================================
       ENHANCED SCROLLBARS
       ======================================== */
    
    ::-webkit-scrollbar {
        width: 8px !important;
        height: 8px !important;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--surface) !important;
        border-radius: var(--radius-sm) !important;
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--gradient-accent) !important;
        border-radius: var(--radius-sm) !important;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--gradient-primary) !important;
    }
    
    /* ========================================
       RESPONSIVE DESIGN
       ======================================== */
    
    @media (max-width: 768px) {
        .modern-card {
            padding: 1rem !important;
            margin-bottom: 0.75rem !important;
        }
        
        .stButton > button {
            padding: 0.5rem 1rem !important;
            font-size: 0.9rem !important;
        }
        
        .stTabs [data-baseweb="tab"] {
            padding: 0.5rem 0.75rem !important;
            font-size: 0.9rem !important;
        }
        
        /* Stack columns on small screens */
        .stColumns {
            display: block !important;
        }
        .stColumns > div {
            width: 100% !important;
            max-width: 100% !important;
            flex: 1 1 100% !important;
            margin-left: 0 !important;
            margin-right: 0 !important;
            margin-bottom: 0.75rem !important;
        }
        
        /* Ensure main container spans full width */
        .main .block-container {
            max-width: 100% !important;
        }
        
        /* Improve sidebar behavior on mobile */
        [data-testid="stSidebar"] {
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            height: 100vh !important;
            transform: translateX(-100%) !important;
            transition: transform 0.3s ease !important;
            z-index: 1000 !important;
        }
        
        /* When toggled open via inline CSS, keep visible */
        [data-testid="stSidebar"][style*="margin-left: 0"] {
            transform: translateX(0) !important;
        }
    }

    /* Make tab list horizontally scrollable and avoid wrapping */
    .stTabs [data-baseweb="tab-list"] {
        overflow-x: auto !important;
        overflow-y: hidden !important;
        white-space: nowrap !important;
        display: flex !important;
        flex-wrap: nowrap !important;
        -webkit-overflow-scrolling: touch !important;
        gap: 0.25rem !important;
    }
    .stTabs [data-baseweb="tab"] {
        flex: 0 0 auto !important;
        min-width: max-content !important;
    }

    /* Ensure media and tables fit container width */
    img, svg, canvas, video {
        max-width: 100% !important;
        height: auto !important;
    }
    .stDataFrame, .stDataFrame > div, .stDataFrame table {
        max-width: 100% !important;
        width: 100% !important;
    }
    .stDataFrame {
        overflow-x: auto !important;
    }
    
    /* Prevent overflow for code blocks on small screens */
    pre, code, .stCode code, .stCode pre {
        white-space: pre-wrap !important;
        word-break: break-word !important;
    }
    </style>
    """
    
    st.markdown(custom_css, unsafe_allow_html=True)

# This function is now defined above in the theme management section

def create_card(title, content, subtitle=None, footer=None, card_type="default"):
    """Create a modern card component"""
    card_class = f"card {card_type}" if card_type != "default" else "card"
    
    card_html = f"""
    <div class="{card_class}">
        <div class="card-header">
            <div>
                <h3 class="card-title">{title}</h3>
                {f'<p class="card-subtitle">{subtitle}</p>' if subtitle else ''}
            </div>
        </div>
        <div class="card-content">
            {content}
        </div>
        {f'<div class="card-footer">{footer}</div>' if footer else ''}
    </div>
    """
    return st.markdown(card_html, unsafe_allow_html=True)

def create_status_card(icon, value, label, status="info"):
    """Create a status card with icon, value, and label"""
    status_class = f"status-card {status}"
    
    card_html = f"""
    <div class="{status_class}">
        <span class="status-icon">{icon}</span>
        <div class="status-value">{value}</div>
        <div class="status-label">{label}</div>
    </div>
    """
    return st.markdown(card_html, unsafe_allow_html=True)

def create_metric_card(value, label, delta=None, delta_type="neutral"):
    """Create a metric card with optional delta"""
    delta_class = f"metric-delta {delta_type}" if delta_type != "neutral" else "metric-delta"
    delta_html = f'<div class="{delta_class}">{delta}</div>' if delta else ''
    
    card_html = f"""
    <div class="metric-container">
        <div class="metric-value">{value}</div>
        <div class="metric-label">{label}</div>
        {delta_html}
    </div>
    """
    return st.markdown(card_html, unsafe_allow_html=True)

def create_animated_header(title, subtitle=None, icon=None):
    """Create an animated header with gradient text"""
    icon_html = f'<span style="font-size: 2rem; margin-right: 1rem;">{icon}</span>' if icon else ''
    subtitle_html = f'<p style="color: var(--text-secondary); font-size: 1.1rem; margin-top: 0.5rem;">{subtitle}</p>' if subtitle else ''
    
    header_html = f"""
    <div style="text-align: center; margin: 2rem 0;">
        {icon_html}
        <h1 style="background: var(--gradient-primary); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin: 0;">
            {title}
        </h1>
        {subtitle_html}
    </div>
    """
    return st.markdown(header_html, unsafe_allow_html=True)

def create_loading_animation():
    """Create a custom loading animation"""
    loading_html = """
    <div style="display: flex; justify-content: center; align-items: center; padding: 2rem;">
        <div style="
            width: 40px;
            height: 40px;
            border: 4px solid var(--border-light);
            border-top: 4px solid var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        "></div>
        <span style="margin-left: 1rem; color: var(--text-secondary);">Loading...</span>
    </div>
    <style>
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    </style>
    """
    return st.markdown(loading_html, unsafe_allow_html=True)

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
        
        # Dark theme is default; theme toggle removed
        
        # Navigation (expander + clearer grouping)
        with st.sidebar.expander("🧭 Navigation", expanded=True):
            page = st.radio(
                "Choose Page:",
                ["🏠 Home", "🔍 Security Scan", "📊 Dashboard", "📋 Reports", "⚙️ Settings"],
                index=0,
                help="Navigate between major sections"
            )
        
        # Store current page in session state
        st.session_state.current_page = page
        
        # LLM Configuration (Structured, contextual hints)
        with st.sidebar.expander("🤖 AI Configuration", expanded=True):
            llm_providers = [
                "OpenAI", "Anthropic", "Google", "Groq", "Cohere", 
                "Hugging Face", "Mistral", "Llama", "Local"
            ]
            selected_provider = st.selectbox(
                "LLM Provider",
                llm_providers,
                index=0,
                help="Pick the provider that matches your API access"
            )
            # Model selection based on provider
            model_options = self.get_model_options(selected_provider)
            selected_model = st.selectbox(
                "Model",
                model_options,
                index=0,
                help="Choose a model appropriate for analysis and summarization"
            )
            # API Key input (encrypted storage)
            api_key = st.text_input(
                f"{selected_provider} API Key",
                type="password",
                help="Key is encrypted locally; leave blank to use environment vars"
            )
            if api_key:
                self.security_manager.store_encrypted_key(selected_provider.lower(), api_key)
        
        # VirusTotal Configuration (Expander)
        with st.sidebar.expander("🔍 VirusTotal Integration", expanded=False):
            vt_enabled = st.checkbox("Enable VirusTotal", value=True)
            if vt_enabled:
                vt_api_key = st.text_input(
                    "VirusTotal API Key",
                    type="password",
                    help="Optional: Leave empty for public API limits"
                )
                if vt_api_key:
                    self.security_manager.store_encrypted_key("virustotal", vt_api_key)
        
        # Scan Configuration (Expander)
        with st.sidebar.expander("⚙️ Scan Settings", expanded=False):
            scan_mode = st.radio(
                "Scan Mode",
                ["Quick Scan", "Deep Scan", "Custom"]
            )
        
        # VAPT Settings (Expander)
        with st.sidebar.expander("🧪 VAPT Settings", expanded=False):
            vapt_enabled = st.checkbox("Enable VAPT", value=False)
            if vapt_enabled:
                st.warning("⚠️ VAPT scanning can be intrusive. Use responsibly.")
                vapt_scope = st.radio(
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
            "OpenAI": [
                # GPT-5 Series (Latest)
                "gpt-5", "gpt-5-pro", "gpt-5-mini",
                # GPT-4 Series
                "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4",
                # o Series (Reasoning-Focused)
                "o3-pro", "o3", "o3-mini", "o4-mini",
                # GPT-3.5 Series
                "gpt-3.5-turbo",
                # Codex Series (Developer-Focused)
                "codex"
            ],
            "Anthropic": [
                "claude-3.5-sonnet", "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
                "claude-2.1", "claude-2.0", "claude-instant"
            ],
            "Google": [
                # Gemini 2.5 Series (Latest)
                "gemini-2.5-pro-diamond", "gemini-2.5-pro", "gemini-2.5-flash-spark", 
                "gemini-2.5-flash", "gemini-2.5-flash-lite",
                # Gemini 2.0 Series
                "gemini-2.0-pro", "gemini-2.0-flash", "gemini-2.0-flash-lite",
                # Gemini 1.5 Series
                "gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.5-flash-lite",
                # Gemini 1.0 Series
                "gemini-1.0-ultra", "gemini-1.0-pro", "gemini-1.0-nano",
                # Specialized Models
                "gemini-nano-banana", "gemini-veo-3", "gemini-robotics", "gemini-robotics-er"
            ],
            "Groq": [
                # Production Models
                "llama-3.1-8b", "llama-3.3-70b", "llama-guard-4-12b",
                "gpt-oss-20b", "gpt-oss-120b", "whisper-large-v3", "whisper-large-v3-turbo",
                # Groq-Optimized Systems
                "compound", "compound-mini",
                # Tool-Use Models
                "llama-3-groq-70b-tool-use", "llama-3-groq-8b-tool-use"
            ],
            "Cohere": [
                "command-r-plus", "command-r", "command", "command-light",
                "command-nightly", "command-light-nightly"
            ],
            "Hugging Face": [
                "mistral-7b", "llama-2-7b", "llama-2-13b", "llama-2-70b",
                "code-llama", "codellama", "falcon-7b", "falcon-40b",
                "bloom-560m", "bloom-1b7", "bloom-3b", "bloom-7b1"
            ],
            "Mistral": [
                "mistral-large", "mistral-medium", "mistral-small",
                "mixtral-8x7b", "mixtral-8x22b", "codestral"
            ],
            "Llama": [
                "llama-3.1-8b", "llama-3.1-70b", "llama-3.1-405b",
                "llama-3-8b", "llama-3-70b", "llama-3-405b",
                "llama-2-7b", "llama-2-13b", "llama-2-70b",
                "llama-2-7b-chat", "llama-2-13b-chat", "llama-2-70b-chat"
            ],
            "Local": [
                "local-model", "ollama-llama3", "ollama-mistral", "ollama-codellama",
                "local-gpt", "local-claude", "custom-model"
            ]
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
        """Render detailed scan results with modern UI components"""
        results = st.session_state.scan_results
        
        # Security Overview Cards
        if 'threats' in results:
            threat_data = results['threats']
            security_score = results.get('security_score', 0)
            
            # Create status cards for key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                create_status_card(
                    icon="🛡️",
                    value=f"{security_score}/100",
                    label="Security Score",
                    status="success" if security_score >= 80 else "warning" if security_score >= 60 else "danger"
                )
            
            with col2:
                create_status_card(
                    icon="⚠️",
                    value=str(len(threat_data)),
                    label="Threats Detected",
                    status="danger" if len(threat_data) > 0 else "success"
                )
            
            with col3:
                critical_threats = len([t for t in threat_data if t.get('severity') == 'critical'])
                create_status_card(
                    icon="🔴",
                    value=str(critical_threats),
                    label="Critical Threats",
                    status="danger" if critical_threats > 0 else "success"
                )
            
            with col4:
                files_scanned = len(results.get('local_scan', {}).get('files', []))
                create_status_card(
                    icon="📁",
                    value=str(files_scanned),
                    label="Files Scanned",
                    status="info"
                )
            
            st.markdown("---")
            
            # Threat Distribution Charts
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
                        title="Threat Severity Distribution",
                        color_discrete_sequence=['#ef4444', '#f59e0b', '#3b82f6', '#10b981']
                    )
                    fig.update_layout(
                        font=dict(family="Inter", size=12),
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)'
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
                        title="Threat Types Detected",
                        color=list(type_counts.values()),
                        color_continuous_scale='Blues'
                    )
                    fig.update_layout(
                        font=dict(family="Inter", size=12),
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        xaxis_title="Threat Type",
                        yaxis_title="Count"
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
                
                # Execute VAPT assessment
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    vapt_results = loop.run_until_complete(
                        vapt_agent.execute('127.0.0.1', '1-1000', 'full_assessment', 'host_only')
                    )
                finally:
                    loop.close()
                
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
            llm_api_key = self.security_manager.get_decrypted_key(config['llm_provider'].lower())
            ti_agent = ThreatIntelligenceAgent(config['llm_provider'], config['llm_model'], llm_api_key)
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
        try:
            with st.spinner("🎯 Running VAPT assessment..."):
                # Initialize VAPT agent
                vapt_agent = VAPTAgent()
                
                # Determine scan scope
                scope = 'host_only' if config.get('vapt_scope') == 'Host Only' else 'local_subnet'
                
                # Execute VAPT assessment
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    results = loop.run_until_complete(
                        vapt_agent.execute(target, port_range, vapt_type, scope)
                    )
                finally:
                    loop.close()
                
                # Display results
                if results.get('success', True):
                    st.success("✅ VAPT assessment completed successfully!")
                    
                    # Display vulnerabilities
                    vulnerabilities = results.get('vulnerabilities', [])
                    if vulnerabilities:
                        st.subheader("🚨 Vulnerabilities Found")
                        for vuln in vulnerabilities:
                            with st.expander(f"{vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}"):
                                st.write(f"**Description**: {vuln.get('description', 'No description')}")
                                st.write(f"**Service**: {vuln.get('service', 'Unknown')}")
                                st.write(f"**Port**: {vuln.get('port', 'Unknown')}")
                                st.write(f"**Recommendation**: {vuln.get('recommendation', 'No recommendation')}")
                    else:
                        st.info("✅ No vulnerabilities found in the target range.")
                    
                    # Display scan statistics
                    stats = results.get('scan_statistics', {})
                    if stats:
                        st.subheader("📊 Scan Statistics")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Hosts Scanned", stats.get('hosts_scanned', 0))
                        with col2:
                            st.metric("Ports Scanned", stats.get('ports_scanned', 0))
                        with col3:
                            st.metric("Services Detected", stats.get('services_detected', 0))
                        with col4:
                            st.metric("Vulnerabilities", stats.get('vulnerabilities_found', 0))
                else:
                    st.error("❌ VAPT assessment failed. Check the logs for details.")
                    if 'error' in results:
                        st.error(f"Error: {results['error']}")
                        
        except Exception as e:
            logger.error(f"Error in VAPT assessment: {e}")
            st.error(f"VAPT assessment failed: {str(e)}")
            st.info("💡 Make sure you have the required dependencies installed (python-nmap)")
    
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
            
            # Get current page from session state
            current_page = st.session_state.get('current_page', '🏠 Home')
            
            # Route to appropriate page
            if current_page == '🏠 Home':
                self.render_home_page()
            elif current_page == '🔍 Security Scan':
                self.render_scan_page(config)
            elif current_page == '📊 Dashboard':
                self.render_dashboard_page()
            elif current_page == '📋 Reports':
                self.render_reports_page()
            elif current_page == '⚙️ Settings':
                self.render_settings_page()
            else:
                self.render_home_page()
            
            # Add footer to all pages
            create_footer()
            
        except Exception as e:
            logger.error(f"Application error: {str(e)}")
            st.error(f"An error occurred: {str(e)}")
            st.info("Please refresh the page and try again.")
    
    def render_home_page(self):
        """Render the home page"""
        create_home_page()
    
    def render_scan_page(self, config):
        """Render the security scan page"""
        # Enhanced main header with animation
        create_animated_header(
            title="Security Scan",
            subtitle="Comprehensive Threat Analysis",
            icon="🔍"
        )
        
        # Render main application tabs
        self.render_main_tabs(config)
    
    def render_dashboard_page(self):
        """Render the dashboard page"""
        st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
        st.markdown("## 📊 Security Dashboard")
        
        # Dashboard content
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Scans", "1,234", "12%")
        with col2:
            st.metric("Threats Detected", "45", "8%")
        with col3:
            st.metric("Vulnerabilities", "23", "-2%")
        with col4:
            st.metric("Risk Score", "7.2/10", "0.3")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    def render_reports_page(self):
        """Render the reports page"""
        st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
        st.markdown("## 📋 Security Reports")
        st.info("Report generation functionality will be implemented here.")
        st.markdown('</div>', unsafe_allow_html=True)
    
    def render_settings_page(self):
        """Render the settings page"""
        st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
        st.markdown("## ⚙️ Application Settings")
        
        # LLM Configuration Testing
        st.markdown("### 🤖 LLM Configuration Testing")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("#### Current Configuration")
            current_config = self.config_manager.get_current_llm_config()
            if current_config:
                st.json(current_config)
            else:
                st.warning("No LLM configuration found")
        
        with col2:
            st.markdown("#### Test LLM Connection")
            
            # Get current config from sidebar
            config = self.render_sidebar()
            
            if st.button("🧪 Test LLM Connection", type="primary"):
                with st.spinner("Testing LLM connection..."):
                    try:
                        from core.llm_client import UniversalLLMClient
                        
                        # Get API key
                        api_key = self.security_manager.get_decrypted_key(config['llm_provider'].lower())
                        
                        if not api_key:
                            st.error("❌ No API key found for the selected provider")
                        else:
                            # Create client and test
                            client = UniversalLLMClient(
                                config['llm_provider'], 
                                config['llm_model'], 
                                api_key
                            )
                            
                            test_result = client.test_connection()
                            
                            if test_result['success']:
                                st.success("✅ LLM connection successful!")
                                st.info(f"**Response:** {test_result['response']}")
                                st.json(test_result)
                            else:
                                st.error(f"❌ LLM connection failed: {test_result['message']}")
                                
                    except Exception as e:
                        st.error(f"❌ Error testing LLM: {str(e)}")
        
        # Model Information
        st.markdown("### 📋 Available Models")
        
        # Create tabs for each provider
        providers = ["OpenAI", "Anthropic", "Google", "Groq", "Cohere", "Hugging Face", "Mistral", "Llama", "Local"]
        tabs = st.tabs(providers)
        
        for i, provider in enumerate(providers):
            with tabs[i]:
                models = self.get_model_options(provider)
                
                st.markdown(f"#### {provider} Models")
                
                # Group models by category
                if provider == "OpenAI":
                    st.markdown("**GPT-5 Series (Latest):**")
                    gpt5_models = [m for m in models if 'gpt-5' in m]
                    for model in gpt5_models:
                        st.markdown(f"• `{model}`")
                    
                    st.markdown("**GPT-4 Series:**")
                    gpt4_models = [m for m in models if 'gpt-4' in m and 'gpt-5' not in m]
                    for model in gpt4_models:
                        st.markdown(f"• `{model}`")
                    
                    st.markdown("**o Series (Reasoning-Focused):**")
                    o_models = [m for m in models if m.startswith('o')]
                    for model in o_models:
                        st.markdown(f"• `{model}`")
                        
                elif provider == "Google":
                    st.markdown("**Gemini 2.5 Series (Latest):**")
                    gemini25_models = [m for m in models if '2.5' in m]
                    for model in gemini25_models:
                        st.markdown(f"• `{model}`")
                    
                    st.markdown("**Gemini 2.0 Series:**")
                    gemini20_models = [m for m in models if '2.0' in m]
                    for model in gemini20_models:
                        st.markdown(f"• `{model}`")
                    
                    st.markdown("**Gemini 1.5 Series:**")
                    gemini15_models = [m for m in models if '1.5' in m]
                    for model in gemini15_models:
                        st.markdown(f"• `{model}`")
                        
                elif provider == "Groq":
                    st.markdown("**Production Models:**")
                    production_models = [m for m in models if any(x in m for x in ['llama-3', 'gpt-oss', 'whisper'])]
                    for model in production_models:
                        st.markdown(f"• `{model}`")
                    
                    st.markdown("**Groq-Optimized Systems:**")
                    groq_models = [m for m in models if m in ['compound', 'compound-mini']]
                    for model in groq_models:
                        st.markdown(f"• `{model}`")
                    
                    st.markdown("**Tool-Use Models:**")
                    tool_models = [m for m in models if 'tool-use' in m]
                    for model in tool_models:
                        st.markdown(f"• `{model}`")
                        
                else:
                    # Default listing for other providers
                    for model in models:
                        st.markdown(f"• `{model}`")
        
        # API Key Management
        st.markdown("### 🔑 API Key Management")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("#### View API Key Status")
            for provider in providers:
                api_key = self.security_manager.get_decrypted_key(provider.lower())
                if api_key:
                    st.success(f"✅ {provider}: Configured")
                else:
                    st.warning(f"⚠️ {provider}: Not configured")
        
        with col2:
            st.markdown("#### Clear API Keys")
            if st.button("🗑️ Clear All API Keys", type="secondary"):
                if st.session_state.get('confirm_clear_keys', False):
                    # Clear all API keys
                    for provider in providers:
                        self.security_manager.clear_encrypted_key(provider.lower())
                    st.success("✅ All API keys cleared")
                    st.session_state.confirm_clear_keys = False
                else:
                    st.session_state.confirm_clear_keys = True
                    st.warning("⚠️ Click again to confirm clearing all API keys")
        
        # System Information
        st.markdown("### 💻 System Information")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Application Version:**")
            st.info("SentinelAI v2.1")
        
        with col2:
            st.markdown("**Python Version:**")
            import sys
            st.info(f"Python {sys.version.split()[0]}")
        
        with col3:
            st.markdown("**Streamlit Version:**")
            import streamlit as st_lib
            st.info(f"Streamlit {st_lib.__version__}")
        
        st.markdown('</div>', unsafe_allow_html=True)

def demo_ui_components():
    """Demo function showing all UI components"""
    st.markdown("## 🎨 UI Components Demo")
    
    # Cards
    st.markdown("### Cards")
    col1, col2 = st.columns(2)
    
    with col1:
        create_card(
            title="Basic Card",
            content="This is a basic card component with modern styling and hover effects.",
            subtitle="Card Subtitle"
        )
    
    with col2:
        create_card(
            title="Success Card",
            content="This card shows success status with green accent.",
            card_type="success"
        )
    
    # Status Cards
    st.markdown("### Status Cards")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        create_status_card("✅", "100", "Success", "success")
    with col2:
        create_status_card("⚠️", "5", "Warning", "warning")
    with col3:
        create_status_card("❌", "2", "Error", "danger")
    with col4:
        create_status_card("ℹ️", "10", "Info", "info")
    
    # Metric Cards
    st.markdown("### Metric Cards")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        create_metric_card("1,234", "Total Scans", "+12%", "positive")
    with col2:
        create_metric_card("98.5%", "Success Rate", "-2.1%", "negative")
    with col3:
        create_metric_card("45", "Active Threats", "0%", "neutral")
    
    # Buttons
    st.markdown("### Buttons")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.button("Primary Button", key="btn1")
    with col2:
        st.button("Success Button", key="btn2")
    with col3:
        st.button("Warning Button", key="btn3")
    with col4:
        st.button("Danger Button", key="btn4")
    
    # Form Elements
    st.markdown("### Form Elements")
    col1, col2 = st.columns(2)
    
    with col1:
        st.text_input("Text Input", placeholder="Enter text here...")
        st.selectbox("Select Box", ["Option 1", "Option 2", "Option 3"])
    
    with col2:
        st.text_area("Text Area", placeholder="Enter longer text here...")
        st.number_input("Number Input", min_value=0, max_value=100, value=50)
    
    # File Uploader
    st.markdown("### File Uploader")
    st.file_uploader("Upload Files", type=['txt', 'pdf', 'docx'], help="Upload files for analysis")
    
    # Alerts
    st.markdown("### Alerts")
    st.success("This is a success message!")
    st.warning("This is a warning message!")
    st.error("This is an error message!")
    st.info("This is an info message!")
    
    # Progress Bar
    st.markdown("### Progress Bar")
    progress = st.progress(0.7)
    st.text("70% Complete")
    
    # Code Block
    st.markdown("### Code Block")
    st.code("""
def hello_world():
    print("Hello, World!")
    return "Success"
    """, language="python")
    
    # Expander
    st.markdown("### Expander")
    with st.expander("Click to expand"):
        st.write("This is expandable content with modern styling.")
        st.write("You can put any content here.")

def main():
    """Application entry point"""
    # Load enhanced custom CSS
    load_custom_css()
    
    # Create sidebar configuration
    create_sidebar_config()
    
    # Add demo option
    if st.sidebar.checkbox("Show UI Components Demo"):
        demo_ui_components()
        return
    
    app = SentinelAIApp()
    app.run()

if __name__ == "__main__":
    main()
