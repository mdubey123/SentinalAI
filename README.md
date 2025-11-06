# SentinelAI v2 - Enterprise Cybersecurity Analysis Platform

## Overview

SentinelAI v2 is a comprehensive, AI-powered cybersecurity analysis platform designed by Dr. Alexandra Chen. It provides enterprise-grade malware detection, vulnerability assessment, and intelligent threat analysis with gamification features and multi-LLM support   .

## Key Features

### 🔍 **Multi-Engine Malware Detection**
- **Local Scanning**: SHA256 + fuzzy hashing (TLSH/ppdeep), ClamAV + YARA rule-based detection
- **VirusTotal Integration**: Hash lookup optimization, file upload for unknown samples
- **Intelligent Caching**: Reduces API calls and improves performance
- **Quota Management**: Automatic fallback to local-only analysis when limits exceeded

### 🎯 **Vulnerability Assessment & Penetration Testing (VAPT)**
- **Host-Only Scanning**: Safe default mode for authorized testing
- **Network Discovery**: Port scanning and service fingerprinting
- **CVE Integration**: Automated vulnerability identification and scoring
- **Risk Assessment**: CVSS-based severity classification

### 🤖 **AI-Powered Threat Intelligence**
- **Multi-LLM Support**: OpenAI, Anthropic, Google, Cohere, Hugging Face, Mistral, Llama
- **Dual Storytelling**: Narrative attacker diary + analytical TTP breakdown
- **Framework Mapping**: MITRE ATT&CK tactics, NIST CSF functions, CVSS scoring
- **Threat Classification**: Ransomware, Trojans, Spyware, Worms, Rootkits, Adware

### 🎮 **Gamification System**
- **Security Posture Scoring**: 0-100 scale with trend tracking
- **Achievement Badges**: Milestone rewards for security improvements
- **Level Progression**: User advancement through security expertise
- **Leaderboard Support**: Multi-profile comparison and competition

### 📊 **Comprehensive Reporting**
- **Executive Reports**: Non-technical, management-friendly PDF summaries
- **Technical Reports**: Detailed analysis with MITRE ATT&CK mapping
- **SIEM Integration**: JSON exports in Common Event Format (CEF)
- **Interactive Dashboards**: Real-time visualization with Plotly charts

### 🔒 **Enterprise Security**
- **Zero-Trust Architecture**: Local-only operation with encrypted API keys
- **Audit Logging**: Complete security event tracking
- **Prompt Injection Protection**: AI safety measures
- **Input Sanitization**: Comprehensive validation and filtering

## Installation

### Prerequisites
\`\`\`bash
# Python 3.8+ required
python --version

# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install clamav clamav-daemon yara python3-dev

# Install system dependencies (macOS)
brew install clamav yara

# Install system dependencies (Windows)
# Download ClamAV and YARA from official websites
\`\`\`

### Python Dependencies
\`\`\`bash
# Install from requirements.txt
pip install -r requirements.txt

# Or install manually
pip install streamlit pandas plotly python-nmap yara-python pyclamd tlsh-python ppdeep reportlab cryptography requests asyncio
\`\`\`

### Setup Script
\`\`\`bash
# Run the automated setup
python scripts/install_dependencies.py
\`\`\`

## Quick Start

### 1. Launch the Application
\`\`\`bash
streamlit run app.py
\`\`\`

### 2. Configure Your LLM
- Select your preferred AI provider (OpenAI, Anthropic, etc.)
- Enter your API key (encrypted and stored locally)
- Choose the appropriate model for your use case

### 3. Configure VirusTotal (Optional)
- Enable VirusTotal integration in the sidebar
- Add your VirusTotal API key for enhanced threat intelligence
- Public API limits apply if no key is provided

### 4. Run Your First Scan
- Navigate to the **Scanner** tab
- Select "Folder Scan" and enter a directory path
- Enable recursive scanning and system directory exclusion
- Click "Start Folder Scan" to begin the analysis

### 5. Review Results
- Monitor real-time progress in the scan status panel
- View comprehensive results in the **Dashboard** tab
- Generate reports in the **Reports** tab
- Track your security improvements over time

## End-to-End Workflow

SentinelAI v2 follows a comprehensive 7-step workflow:

\`\`\`
1. Config Manager Agent
   ├── Initialize selected LLM provider & model
   ├── Secure API keys (encrypted, local storage)
   └── Pass configuration to downstream agents

2. Local Scan Agent
   ├── Generate SHA256 + fuzzy hashes (TLSH/ppdeep)
   ├── Execute ClamAV + YARA scanning
   └── Produce structured JSON results

3. VirusTotal Agent (Optional)
   ├── Query file hashes (quota optimization)
   ├── Upload files <32MB if hash unknown
   ├── Apply intelligent throttling
   └── Fallback to local-only if quota exceeded

4. VAPT Agent (Optional)
   ├── Host-only port scanning (default)
   ├── Optional subnet scanning (with warnings)
   ├── Service fingerprinting & CVE lookup
   └── Configuration weakness detection

5. Threat Intelligence & AI Reasoning Agent
   ├── Aggregate Local + VirusTotal + VAPT results
   ├── Classify malware types and assign severity
   ├── Map to CVSS, MITRE ATT&CK, NIST CSF
   ├── Generate dual storytelling (narrative + analytical)
   └── Provide remediation guidance

6. Report Agent
   ├── Create interactive Streamlit dashboards
   ├── Generate executive PDF reports
   ├── Export technical JSON for SIEM integration
   └── Maintain local persistence for history

7. User Dashboard & Notifications
   ├── Display comprehensive scan results
   ├── Update gamification scores and badges
   ├── Track security posture trends
   └── Provide actionable insights
\`\`\`

## Configuration

### LLM Providers
\`\`\`json
{
  "llm_settings": {
    "default_provider": "OpenAI",
    "default_model": "gpt-4",
    "max_tokens": 4000,
    "temperature": 0.1
  }
}
\`\`\`

### Scan Settings
\`\`\`json
{
  "scan_settings": {
    "max_file_size_mb": 32,
    "exclude_extensions": [".tmp", ".log", ".cache"],
    "exclude_directories": ["/proc", "/sys", "/dev"],
    "recursive_scan": true,
    "hash_algorithms": ["sha256", "fuzzy"]
  }
}
\`\`\`

### Security Settings
\`\`\`json
{
  "security_settings": {
    "audit_logging": true,
    "prompt_injection_protection": true,
    "api_rate_limiting": true,
    "max_requests_per_minute": 60,
    "encryption_enabled": true
  }
}
\`\`\`

## API Integration

### VirusTotal
- **Public API**: 4 requests/minute, 500 requests/day
- **Private API**: Higher limits with paid subscription
- **Supported Operations**: Hash lookup, file upload, detailed reports

### YARA Rules
- **Built-in Rules**: Common malware families and attack patterns
- **Custom Rules**: Add your own detection signatures
- **Rule Categories**: Ransomware, Trojans, Spyware, Rootkits, APT indicators

## Security Considerations

### Data Privacy
- **Local Processing**: All analysis performed locally
- **No Data Transmission**: Files never leave your environment
- **Encrypted Storage**: API keys encrypted with system keyring
- **Audit Trail**: Complete logging of all security events

### Network Security
- **Minimal Network Access**: Only for VirusTotal API calls
- **TLS Encryption**: All external communications secured
- **Proxy Support**: Corporate firewall compatibility
- **Offline Mode**: Full functionality without internet

### Access Control
- **User Profiles**: Multi-user support with separate configurations
- **Permission Levels**: Configurable access to VAPT features
- **Session Management**: Secure handling of authentication tokens

## Troubleshooting

### Common Issues

**ClamAV Not Found**
\`\`\`bash
# Update ClamAV database
sudo freshclam

# Start ClamAV daemon
sudo systemctl start clamav-daemon
\`\`\`

**YARA Rules Missing**
\`\`\`bash
# Check YARA installation
yara --version

# Verify rules directory
ls -la rules/yara/
\`\`\`

**VirusTotal API Errors**
- Verify API key validity
- Check quota limits in VirusTotal dashboard
- Ensure network connectivity

**LLM Connection Issues**
- Validate API key format
- Check provider service status
- Review rate limiting settings

### Performance Optimization

**Large Directory Scans**
- Enable file type filtering
- Use exclude patterns for system directories
- Increase concurrent scan workers

**Memory Usage**
- Adjust max file size limits
- Enable result caching
- Monitor system resources

## Contributing

### Development Setup
\`\`\`bash
# Clone repository
git clone https://github.com/your-org/sentinelai-v2.git
cd sentinelai-v2

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt
\`\`\`

### Code Standards
- **PEP 8**: Python style guide compliance
- **Type Hints**: Full type annotation coverage
- **Documentation**: Comprehensive docstrings
- **Testing**: Unit tests for all components

### Security Guidelines
- **Input Validation**: Sanitize all user inputs
- **Error Handling**: Secure error messages
- **Logging**: Audit all security-relevant events
- **Dependencies**: Regular security updates

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

### Documentation
- **User Guide**: Comprehensive usage instructions
- **API Reference**: Technical implementation details
- **Security Best Practices**: Enterprise deployment guidance

### Community
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community support and questions
- **Security Reports**: Responsible disclosure process

### Professional Support
For enterprise deployments and custom integrations, contact Dr. Alexandra Chen's consulting team.

---

**SentinelAI v2** - *Precision Cybersecurity Analysis*  
Built with ❤️ by Dr. Alexandra Chen using Streamlit, LangChain, and Advanced AI
"# SentinelAI" 
"# SentinalAI" 
