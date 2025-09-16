# SentinelAI v2 - Comprehensive User Guide

## Table of Contents
1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Application Architecture](#application-architecture)
4. [Agent Functions & Capabilities](#agent-functions--capabilities)
5. [Application Sections & Usage](#application-sections--usage)
6. [Configuration Guide](#configuration-guide)
7. [Security Features](#security-features)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)
10. [Contributing](#contributing)

---

## Overview

SentinelAI v2 is an advanced cybersecurity analysis platform that combines multiple security tools with AI-powered threat intelligence. The application provides comprehensive malware detection, vulnerability assessment, and security reporting capabilities.

### Key Features
- **Multi-Agent Architecture**: Specialized agents for different security tasks
- **AI-Powered Analysis**: LLM integration for threat intelligence and reporting
- **Real-time Scanning**: Local file system and network vulnerability scanning
- **VirusTotal Integration**: Cloud-based malware detection
- **Comprehensive Reporting**: PDF and JSON report generation
- **Gamification**: Security score tracking and achievement system
- **Modern UI**: Dark/light theme support with responsive design

### Team
- **Manya Dubey** - Agentic AI, GenAI
- **Meet Solanki** - Data Engineer, Security Analyst
- **Mayush Jain** - DevOps Engineer

---

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Windows 10/11, macOS, or Linux
- 4GB RAM minimum (8GB recommended)
- 2GB free disk space

### Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-repo/SentinelAI.git
   cd SentinelAI
   ```

2. **Install Dependencies**
   ```bash
   # For Windows
   pip install -r requirements_windows.txt
   
   # For Linux/macOS
   pip install -r requirements.txt
   ```

3. **Install Additional Dependencies (Optional)**
   ```bash
   # For PDF report generation
   python install_pdf_deps.py
   
   # For Docker deployment
   docker-compose up -d
   ```

4. **Run the Application**
   ```bash
   # Windows
   SentinelAI.bat
   
   # Linux/macOS
   streamlit run app.py
   ```

### First-Time Setup

1. **Configure API Keys** (Optional but recommended)
   - Navigate to Settings page
   - Add your API keys for enhanced functionality:
     - OpenAI/Anthropic/Google for AI analysis
     - VirusTotal for cloud malware detection

2. **Verify Installation**
   - Open the application in your browser
   - Check that all agents are initialized
   - Run a test scan on a sample file

---

## Application Architecture

### Core Components

#### 1. **Base Agent System**
- **File**: `agents/base_agent.py`
- **Purpose**: Provides common functionality for all specialized agents
- **Key Features**:
  - Operation timing and logging
  - Input validation and sanitization
  - Error handling and caching
  - Security audit logging

#### 2. **Configuration Management**
- **File**: `core/config_manager.py`
- **Purpose**: Manages application settings and LLM configurations
- **Key Features**:
  - Dynamic configuration loading
  - LLM provider validation
  - Workflow optimization settings

#### 3. **Security Management**
- **File**: `core/security_manager.py`
- **Purpose**: Handles encryption, API key management, and security controls
- **Key Features**:
  - Encrypted API key storage
  - Input sanitization
  - Prompt injection protection
  - Audit logging

#### 4. **Gamification Engine**
- **File**: `core/gamification.py`
- **Purpose**: Tracks user progress and achievements
- **Key Features**:
  - Security score calculation
  - Achievement system
  - Progress tracking

---

## Agent Functions & Capabilities

### 1. Local Scan Agent (`agents/local_scan_agent.py`)

**Purpose**: Performs local file system scanning and malware detection

#### Key Functions:

##### `execute(scan_path, recursive=True, exclude_system=True)`
- **Purpose**: Main scanning function
- **Parameters**:
  - `scan_path`: Path to file or directory to scan
  - `recursive`: Whether to scan subdirectories
  - `exclude_system`: Whether to exclude system directories
- **Returns**: Dictionary with scan results, threats, and statistics

##### `_scan_file_sync(file_path)`
- **Purpose**: Synchronous file scanning for thread pool execution
- **Features**:
  - File hash generation (MD5, SHA1, SHA256, fuzzy hashing)
  - YARA rule matching
  - ClamAV scanning
  - Signature-based detection

##### `_generate_file_hashes(file_path)`
- **Purpose**: Generate multiple hash types for file identification
- **Returns**: Dictionary with MD5, SHA1, SHA256, and fuzzy hashes

##### `_yara_scan_file(file_path)`
- **Purpose**: Scan files using YARA rules
- **Features**:
  - Custom malware detection rules
  - Pattern matching for suspicious behavior
  - Confidence scoring

##### `_clamav_scan_file(file_path)`
- **Purpose**: Scan files using ClamAV antivirus engine
- **Features**:
  - Real-time malware detection
  - Virus signature matching
  - Threat classification

##### `compare_fuzzy_hashes(hash1, hash2)`
- **Purpose**: Compare file similarity using fuzzy hashing
- **Returns**: Similarity score (0-100)

##### `update_yara_rules(rules_content)`
- **Purpose**: Update YARA rules with new content
- **Features**:
  - Dynamic rule compilation
  - Custom threat detection patterns

#### Usage Example:
```python
from agents.local_scan_agent import LocalScanAgent

agent = LocalScanAgent()
results = agent.scan_folder("/path/to/scan", recursive=True)
print(f"Found {len(results['threats'])} threats")
```

### 2. VirusTotal Agent (`agents/virustotal_agent.py`)

**Purpose**: Integrates with VirusTotal API for cloud-based malware detection

#### Key Functions:

##### `execute(hashes, files_to_upload=None)`
- **Purpose**: Main VirusTotal analysis function
- **Parameters**:
  - `hashes`: List of file hashes to check
  - `files_to_upload`: List of file paths to upload for analysis
- **Returns**: Dictionary with detection results and quota information

##### `_analyze_hashes(hashes)`
- **Purpose**: Analyze file hashes using VirusTotal database
- **Features**:
  - Intelligent caching
  - Rate limiting
  - Quota management

##### `_upload_files(file_paths)`
- **Purpose**: Upload files to VirusTotal for analysis
- **Features**:
  - File size validation
  - Progress tracking
  - Error handling

##### `_parse_file_report(data)`
- **Purpose**: Parse VirusTotal API response
- **Features**:
  - Threat classification
  - Reputation scoring
  - Detection ratio calculation

##### `get_api_status()`
- **Purpose**: Get current API status and configuration
- **Returns**: API key status, quota info, rate limits

##### `set_api_key(api_key)`
- **Purpose**: Set new VirusTotal API key
- **Features**:
  - Key validation
  - Premium/Public detection
  - Encrypted storage

#### Usage Example:
```python
from agents.virustotal_agent import VirusTotalAgent

agent = VirusTotalAgent()
agent.set_api_key("your_virustotal_api_key")
results = agent.analyze_hashes(["hash1", "hash2"])
```

### 3. VAPT Agent (`agents/vapt_agent.py`)

**Purpose**: Performs Vulnerability Assessment and Penetration Testing

#### Key Functions:

##### `execute(target, port_range="1-1000", scan_type="port_scan", scope="host_only")`
- **Purpose**: Main VAPT assessment function
- **Parameters**:
  - `target`: IP address or hostname to scan
  - `port_range`: Port range to scan (e.g., "1-1000", "80,443,8080")
  - `scan_type`: Type of scan (port_scan, service_fingerprinting, vulnerability_scan, full_assessment)
  - `scope`: Scan scope (host_only, local_subnet)
- **Returns**: Dictionary with scan results and vulnerabilities

##### `_port_scan(target, port_range)`
- **Purpose**: Perform port scanning
- **Features**:
  - Nmap integration
  - Basic socket scanning
  - Concurrent port checking

##### `_service_fingerprinting(target, port_range)`
- **Purpose**: Identify services running on open ports
- **Features**:
  - Banner grabbing
  - Service version detection
  - Protocol identification

##### `_vulnerability_scan(target, port_range)`
- **Purpose**: Check for known vulnerabilities
- **Features**:
  - CVE database lookup
  - Risk assessment
  - Remediation recommendations

##### `_fingerprint_service(host, port, service_hint)`
- **Purpose**: Detailed service fingerprinting
- **Features**:
  - SSH, HTTP, FTP, SMTP fingerprinting
  - Version extraction
  - Configuration analysis

##### `_check_service_vulnerabilities(service_info)`
- **Purpose**: Check services for known vulnerabilities
- **Features**:
  - CVE matching
  - Risk classification
  - Patch recommendations

#### Usage Example:
```python
from agents.vapt_agent import VAPTAgent

agent = VAPTAgent()
results = agent.execute("192.168.1.1", "1-1000", "full_assessment")
print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
```

### 4. Threat Intelligence Agent (`agents/threat_intelligence_agent.py`)

**Purpose**: AI-powered threat analysis and classification

#### Key Functions:

##### `execute(scan_results)`
- **Purpose**: Main threat intelligence analysis
- **Parameters**:
  - `scan_results`: Combined results from all scan agents
- **Returns**: Comprehensive threat analysis with AI insights

##### `_classify_threats(aggregated_data)`
- **Purpose**: Classify and normalize threats from all sources
- **Features**:
  - Threat type identification
  - Severity assessment
  - MITRE ATT&CK mapping

##### `_calculate_security_score(threats, aggregated_data)`
- **Purpose**: Calculate overall security posture score (0-100)
- **Features**:
  - Weighted scoring based on threat severity
  - Coverage bonus calculation
  - Risk level determination

##### `_map_to_frameworks(threats)`
- **Purpose**: Map threats to security frameworks
- **Features**:
  - MITRE ATT&CK tactic mapping
  - NIST CSF function alignment
  - CVSS distribution analysis

##### `_generate_ai_analysis(aggregated_data, threats)`
- **Purpose**: Generate AI-powered analysis and storytelling
- **Features**:
  - Narrative threat stories
  - Analytical breakdown
  - Attack timeline reconstruction

##### `_generate_narrative_story(threats)`
- **Purpose**: Create dramatized intrusion stories
- **Features**:
  - Attacker diary format
  - Threat progression narrative
  - Impact assessment

##### `_generate_analytical_breakdown(threats, aggregated_data)`
- **Purpose**: Generate technical TTP analysis
- **Features**:
  - Attack vector identification
  - Persistence mechanism analysis
  - Evasion technique detection

#### Usage Example:
```python
from agents.threat_intelligence_agent import ThreatIntelligenceAgent

agent = ThreatIntelligenceAgent("OpenAI", "gpt-4")
results = agent.analyze_threats(scan_results)
print(f"Security Score: {results['security_score']}/100")
```

### 5. Report Agent (`agents/report_agent.py`)

**Purpose**: Generates comprehensive security reports

#### Key Functions:

##### `execute(analysis_results, report_type="executive")`
- **Purpose**: Main report generation function
- **Parameters**:
  - `analysis_results`: Results from threat intelligence analysis
  - `report_type`: Type of report (executive, technical, compliance)
- **Returns**: Dictionary with generated reports and file paths

##### `_generate_pdf_report(analysis_results, report_type)`
- **Purpose**: Generate PDF reports using ReportLab
- **Features**:
  - Executive summaries
  - Technical details
  - Charts and graphs
  - Professional formatting

##### `_generate_json_report(analysis_results, report_type)`
- **Purpose**: Generate JSON reports for SIEM integration
- **Features**:
  - Machine-readable format
  - CEF event conversion
  - Structured data export

##### `_generate_executive_pdf_content(analysis_results)`
- **Purpose**: Create executive-level PDF content
- **Features**:
  - High-level summaries
  - Risk assessments
  - Priority recommendations

##### `_generate_technical_pdf_content(analysis_results)`
- **Purpose**: Create technical PDF content
- **Features**:
  - Detailed threat analysis
  - MITRE mapping
  - Remediation steps

##### `_convert_to_siem_events(analysis_results)`
- **Purpose**: Convert results to SIEM-compatible events
- **Features**:
  - CEF format conversion
  - Event normalization
  - Timestamp formatting

#### Usage Example:
```python
from agents.report_agent import ReportAgent

agent = ReportAgent()
results = agent.generate_executive_report(analysis_results)
print(f"Report saved to: {results['files_generated'][0]['path']}")
```

---

## Application Sections & Usage

### 1. Home Page

**Purpose**: Welcome page with application overview and team information

#### Features:
- **Hero Section**: Animated title with gradient effects
- **App Description**: Comprehensive overview of capabilities
- **Team Members**: Profiles of development team
- **Workflow Overview**: Step-by-step process explanation
- **Benefits Section**: Key advantages of using SentinelAI
- **Call-to-Action**: Quick start buttons

#### How to Use:
1. Navigate to Home using the sidebar
2. Review the application capabilities
3. Click "Get Started" to begin scanning
4. Explore team member profiles

### 2. Security Scan Page

**Purpose**: Main scanning interface for file and network analysis

#### Features:

##### File Upload Section
- **Drag & Drop**: Upload files directly to the interface
- **File Validation**: Automatic file type and size checking
- **Batch Processing**: Upload multiple files simultaneously

##### Scan Configuration
- **Scan Type Selection**:
  - **Local Scan**: File system malware detection
  - **VirusTotal**: Cloud-based analysis
  - **VAPT**: Network vulnerability assessment
  - **Full Assessment**: Combined analysis

- **Advanced Options**:
  - **Recursive Scanning**: Include subdirectories
  - **System Exclusion**: Skip system files
  - **Port Range**: Customize network scan ports
  - **Scan Scope**: Host-only or subnet scanning

##### Real-time Progress
- **Progress Bars**: Visual scan progress indicators
- **Status Updates**: Live scan status messages
- **Statistics**: Files scanned, threats found, time elapsed

#### How to Use:
1. **Select Scan Type**:
   - Choose from Local Scan, VirusTotal, VAPT, or Full Assessment
   
2. **Configure Target**:
   - **For Files**: Upload files or specify directory path
   - **For Network**: Enter IP address or hostname
   
3. **Set Parameters**:
   - Adjust scan options based on your needs
   - Configure port ranges for network scans
   
4. **Start Scan**:
   - Click "Start Security Scan" button
   - Monitor progress in real-time
   
5. **Review Results**:
   - View detected threats and vulnerabilities
   - Access detailed analysis reports

### 3. Dashboard Page

**Purpose**: Centralized view of security metrics and recent activity

#### Features:

##### Security Metrics
- **Security Score**: Overall security posture (0-100)
- **Threat Count**: Total threats detected
- **Risk Level**: Current risk assessment
- **Scan Statistics**: Files scanned, vulnerabilities found

##### Visual Analytics
- **Threat Distribution Chart**: Pie chart of threat types
- **Timeline Graph**: Threat detection over time
- **Risk Assessment**: Bar chart of risk levels
- **Geographic Map**: Threat origin locations (if available)

##### Recent Activity
- **Scan History**: List of recent scans
- **Threat Alerts**: Latest threat detections
- **System Events**: Security-related events
- **Performance Metrics**: Scan speed and efficiency

##### Quick Actions
- **Start New Scan**: Quick scan initiation
- **View Reports**: Access generated reports
- **Export Data**: Download scan results
- **Settings**: Configure application settings

#### How to Use:
1. **Monitor Security Posture**:
   - Check security score and risk level
   - Review threat distribution charts
   
2. **Analyze Trends**:
   - View timeline graphs for threat patterns
   - Identify security improvement areas
   
3. **Take Action**:
   - Use quick action buttons for common tasks
   - Access detailed reports for specific scans
   
4. **Track Progress**:
   - Monitor scan history and performance
   - Review system events and alerts

### 4. Reports Page

**Purpose**: Comprehensive reporting and data export functionality

#### Features:

##### Report Types
- **Executive Reports**: High-level summaries for management
- **Technical Reports**: Detailed analysis for security teams
- **Compliance Reports**: Framework-aligned documentation
- **Custom Reports**: User-defined report formats

##### Report Formats
- **PDF Reports**: Professional formatted documents
- **JSON Reports**: Machine-readable data export
- **CSV Reports**: Spreadsheet-compatible data
- **XML Reports**: Structured data format

##### Report Content
- **Executive Summary**: Key findings and recommendations
- **Threat Analysis**: Detailed threat descriptions
- **Risk Assessment**: Risk level and impact analysis
- **Remediation Steps**: Action items and solutions
- **Framework Mapping**: MITRE ATT&CK, NIST CSF alignment

##### Export Options
- **Download Reports**: Direct file download
- **Email Reports**: Automated report delivery
- **SIEM Integration**: Export to security tools
- **API Access**: Programmatic report retrieval

#### How to Use:
1. **Select Report Type**:
   - Choose executive, technical, or compliance report
   
2. **Configure Content**:
   - Select sections to include
   - Set report format and style
   
3. **Generate Report**:
   - Click "Generate Report" button
   - Wait for processing to complete
   
4. **Access Reports**:
   - Download generated files
   - View report preview
   - Share with stakeholders

### 5. Settings Page

**Purpose**: Application configuration and API key management

#### Features:

##### API Configuration
- **LLM Providers**: OpenAI, Anthropic, Google, Cohere, etc.
- **API Key Management**: Secure storage and validation
- **Model Selection**: Choose specific AI models
- **Rate Limiting**: Configure API usage limits

##### Scan Settings
- **File Size Limits**: Maximum file size for scanning
- **Exclusion Lists**: Files and directories to skip
- **Hash Algorithms**: Select hash types for file identification
- **Timeout Settings**: Scan operation timeouts

##### Security Settings
- **Audit Logging**: Enable/disable security logging
- **Encryption**: Configure data encryption options
- **Access Control**: User permissions and restrictions
- **Prompt Protection**: AI prompt injection prevention

##### Performance Settings
- **Concurrent Scans**: Number of simultaneous scans
- **Cache Settings**: Enable/disable result caching
- **Memory Limits**: Resource usage controls
- **Thread Pool**: Background processing configuration

##### Theme Settings
- **Light/Dark Mode**: Visual theme selection
- **Auto Theme**: System preference detection
- **Custom Colors**: Personalized color schemes
- **Accessibility**: High contrast and font options

#### How to Use:
1. **Configure APIs**:
   - Add API keys for enhanced functionality
   - Select preferred LLM providers and models
   
2. **Adjust Scan Settings**:
   - Set file size limits and exclusions
   - Configure scan timeouts and algorithms
   
3. **Security Configuration**:
   - Enable audit logging and encryption
   - Set up access controls and protections
   
4. **Performance Tuning**:
   - Adjust concurrent scan limits
   - Configure caching and memory usage
   
5. **Customize Interface**:
   - Select theme and color preferences
   - Configure accessibility options

---

## Configuration Guide

### Environment Variables

Create a `.env` file in the project root:

```bash
# API Keys (Optional)
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
GOOGLE_API_KEY=your_google_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# Application Settings
SENTINELAI_DEBUG=false
SENTINELAI_LOG_LEVEL=INFO
SENTINELAI_MAX_FILE_SIZE=32
SENTINELAI_CACHE_TTL=3600

# Security Settings
SENTINELAI_ENCRYPTION_KEY=your_encryption_key
SENTINELAI_AUDIT_LOGGING=true
SENTINELAI_RATE_LIMIT=60
```

### Configuration File

The application uses `config.json` for persistent settings:

```json
{
  "app": {
    "name": "SentinelAI v2",
    "version": "2.0.0",
    "debug": false
  },
  "llm": {
    "default_provider": "OpenAI",
    "default_model": "gpt-4",
    "max_tokens": 4000,
    "temperature": 0.1
  },
  "scan_settings": {
    "max_file_size_mb": 32,
    "exclude_extensions": [".tmp", ".log", ".cache"],
    "recursive_scan": true,
    "hash_algorithms": ["sha256", "fuzzy"]
  },
  "virustotal_settings": {
    "enabled": true,
    "api_quota_limit": 500,
    "cache_results": true
  },
  "security_settings": {
    "audit_logging": true,
    "encryption_enabled": true,
    "prompt_injection_protection": true
  }
}
```

### Docker Configuration

For Docker deployment, use `docker-compose.yml`:

```yaml
version: '3.8'
services:
  sentinelai:
    build: .
    ports:
      - "8501:8501"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
    volumes:
      - ./data:/app/data
      - ./reports:/app/reports
    restart: unless-stopped
```

---

## Security Features

### Data Protection
- **Encryption**: All API keys and sensitive data encrypted at rest
- **Secure Storage**: Keys stored in encrypted format with restricted permissions
- **Input Sanitization**: All user inputs validated and sanitized
- **Audit Logging**: Comprehensive security event logging

### API Security
- **Rate Limiting**: Prevents API abuse and quota exhaustion
- **Key Validation**: API key format validation and security checks
- **Prompt Injection Protection**: Prevents AI prompt manipulation
- **Quota Management**: Intelligent API usage tracking and limits

### Network Security
- **Target Validation**: Ensures only authorized targets are scanned
- **Port Restrictions**: Configurable port range limitations
- **Timeout Controls**: Prevents long-running network operations
- **Error Handling**: Secure error messages without information leakage

### Access Control
- **User Authentication**: Optional user authentication system
- **Permission Management**: Role-based access control
- **Session Management**: Secure session handling
- **Activity Monitoring**: User action tracking and logging

---

## Troubleshooting

### Common Issues

#### 1. Application Won't Start
**Symptoms**: Error messages during startup
**Solutions**:
- Check Python version (3.8+ required)
- Verify all dependencies are installed
- Check port 8501 is available
- Review error logs in console

#### 2. API Key Issues
**Symptoms**: API-related errors, quota exceeded
**Solutions**:
- Verify API key format and validity
- Check API quota limits
- Ensure proper key storage permissions
- Review API provider documentation

#### 3. Scan Failures
**Symptoms**: Scans not completing or errors during scanning
**Solutions**:
- Check file permissions and paths
- Verify target accessibility
- Review scan timeout settings
- Check available disk space

#### 4. Performance Issues
**Symptoms**: Slow scans, high memory usage
**Solutions**:
- Reduce concurrent scan limits
- Enable result caching
- Increase system memory
- Optimize scan parameters

#### 5. Report Generation Errors
**Symptoms**: Reports not generating or formatting issues
**Solutions**:
- Install ReportLab dependencies
- Check file write permissions
- Verify template configurations
- Review report content limits

### Log Files

#### Application Logs
- **Location**: `~/.sentinelai/logs/`
- **Files**: `app.log`, `security.log`, `audit.log`
- **Rotation**: Automatic log rotation and cleanup

#### Error Logs
- **Streamlit Logs**: Console output and Streamlit logs
- **Python Logs**: Application-specific error logging
- **System Logs**: Operating system error messages

### Debug Mode

Enable debug mode for detailed logging:

```bash
# Set environment variable
export SENTINELAI_DEBUG=true

# Or modify config.json
{
  "app": {
    "debug": true
  }
}
```

### Support

For additional support:
1. Check the troubleshooting section
2. Review log files for error details
3. Search existing issues on GitHub
4. Create a new issue with detailed information

---

## API Reference

### Agent API

#### LocalScanAgent
```python
class LocalScanAgent(BaseAgent):
    def execute(self, scan_path: str, recursive: bool = True, exclude_system: bool = True) -> Dict[str, Any]
    def scan_folder(self, folder_path: str, recursive: bool = True, exclude_system: bool = True) -> Dict[str, Any]
    def compare_fuzzy_hashes(self, hash1: str, hash2: str) -> Optional[int]
    def update_yara_rules(self, rules_content: str) -> bool
    def get_scan_statistics(self) -> Dict[str, Any]
```

#### VirusTotalAgent
```python
class VirusTotalAgent(BaseAgent):
    def execute(self, hashes: List[str], files_to_upload: Optional[List[str]] = None) -> Dict[str, Any]
    def analyze_hashes(self, hashes: List[str]) -> Dict[str, Any]
    def upload_files(self, file_paths: List[str]) -> Dict[str, Any]
    def set_api_key(self, api_key: str) -> bool
    def get_api_status(self) -> Dict[str, Any]
    def reset_quota(self)
```

#### VAPTAgent
```python
class VAPTAgent(BaseAgent):
    def execute(self, target: str, port_range: str = "1-1000", scan_type: str = "port_scan", scope: str = "host_only") -> Dict[str, Any]
    def get_scan_statistics(self) -> Dict[str, Any]
```

#### ThreatIntelligenceAgent
```python
class ThreatIntelligenceAgent(BaseAgent):
    def execute(self, scan_results: Dict[str, Any]) -> Dict[str, Any]
    def analyze_threats(self, scan_results: Dict[str, Any]) -> Dict[str, Any]
    def generate_attacker_narrative(self, analysis_results: Dict[str, Any]) -> str
    def generate_analytical_breakdown(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]
    def map_to_frameworks(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]
```

#### ReportAgent
```python
class ReportAgent(BaseAgent):
    def execute(self, analysis_results: Dict[str, Any], report_type: str = "executive") -> Dict[str, Any]
    def generate_executive_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]
    def generate_technical_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]
```

### Configuration API

#### ConfigManager
```python
class ConfigManager:
    def get(self, key: str, default: Any = None) -> Any
    def set(self, key: str, value: Any)
    def get_llm_config(self, provider: str, model: str) -> Dict[str, Any]
    def initialize_llm(self, provider: str, model: str) -> Dict[str, Any]
    def get_workflow_config(self) -> Dict[str, Any]
    def validate_config(self) -> bool
    def export_config(self) -> str
    def import_config(self, config_json: str) -> bool
```

#### SecurityManager
```python
class SecurityManager:
    def store_encrypted_key(self, service: str, api_key: str) -> bool
    def get_decrypted_key(self, service: str) -> Optional[str]
    def delete_key(self, service: str) -> bool
    def validate_api_key(self, api_key: str, service: str) -> bool
    def sanitize_input(self, user_input: str) -> str
    def check_prompt_injection(self, prompt: str) -> bool
    def get_audit_logs(self, lines: int = 100) -> list
    def export_security_report(self) -> Dict[str, Any]
```

### Streamlit Integration

#### Main Application Functions
```python
def main()
def initialize_theme_state()
def load_custom_css()
def apply_theme(theme: str)
def create_theme_toggle()
def create_home_page()
def create_footer()
def show_theme_toast(message: str, type: str = "info")
```

#### Performance Functions
```python
@st.cache_data(ttl=300)
def get_cached_scan_results(scan_id: str) -> Optional[Dict]

@st.cache_data(ttl=600)
def get_cached_threat_intelligence(query: str) -> Optional[Dict]

@st.cache_resource
def get_thread_pool()

def validate_api_key(provider: str, api_key: str) -> bool
def secure_input_handler(input_data: str, max_length: int = 1000) -> str
def handle_api_quota(provider: str, operation: str) -> bool
def optimize_scan_performance(scan_type: str, target: str) -> Dict[str, Any]
```

---

## Contributing

### Development Setup

1. **Fork the Repository**
2. **Create Development Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   venv\Scripts\activate  # Windows
   ```

3. **Install Development Dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Run Tests**:
   ```bash
   pytest tests/
   ```

### Code Style

- Follow PEP 8 guidelines
- Use type hints for all functions
- Write comprehensive docstrings
- Include unit tests for new features

### Pull Request Process

1. Create feature branch from main
2. Implement changes with tests
3. Update documentation
4. Submit pull request with description
5. Address review feedback

### Reporting Issues

When reporting issues, include:
- Operating system and version
- Python version
- Error messages and logs
- Steps to reproduce
- Expected vs actual behavior

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- **Streamlit Team** for the excellent web framework
- **OpenAI, Anthropic, Google** for AI model APIs
- **VirusTotal** for malware detection services
- **Security Community** for threat intelligence and best practices

---

*For additional support or questions, please refer to the troubleshooting section or create an issue on GitHub.*
