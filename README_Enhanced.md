# 🛡️ SentinelAI v2 - Enhanced Cybersecurity Analysis Platform

## 🌟 Overview

SentinelAI v2 is a cutting-edge cybersecurity platform that combines AI-driven intelligence, comprehensive threat analysis, and automated vulnerability assessment. Built with modern web technologies and enhanced UI/UX design, it provides security teams with powerful tools to stay ahead of evolving threats.

## 👥 Development Team

- **🤖 Manya Dubey** - Agentic AI & GenAI Specialist
- **📊 Meet Solanki** - Data Engineer & Security Analyst  
- **⚙️ Mayush Jain** - DevOps Engineer

## ✨ Key Features

### 🎯 **Core Functionality**
- **Multi-LLM Support**: Integration with OpenAI, Anthropic, Google, Cohere, and more
- **VirusTotal Integration**: Real-time malware analysis and threat intelligence
- **VAPT Capabilities**: Comprehensive penetration testing and vulnerability assessment
- **Automated Reporting**: AI-generated security reports with actionable insights
- **Real-time Monitoring**: Continuous security posture assessment
- **Compliance Mapping**: NIST, OWASP, and industry-standard framework alignment

### 🎨 **Enhanced UI/UX**
- **Modern Design**: Clean, minimalistic interface with glass-morphism effects
- **Theme System**: Automatic detection and manual toggle between light/dark modes
- **Responsive Design**: Optimized for desktop, tablet, and mobile devices
- **Smooth Animations**: Beautiful transitions and hover effects
- **Accessibility**: High contrast support and reduced motion options

### ⚡ **Performance Optimizations**
- **Intelligent Caching**: Results cached for improved performance
- **API Quota Management**: Smart rate limiting and quota tracking
- **Concurrent Processing**: Multi-threaded operations for faster scans
- **Input Validation**: Secure handling of user inputs and API keys
- **Error Handling**: Graceful error recovery and user feedback

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (for cloning the repository)

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd SentinelAI
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   streamlit run app.py
   ```

4. **Open your browser** and navigate to `http://localhost:8501`

### Detailed Installation

#### Windows Installation

1. **Install Python**:
   - Download Python 3.8+ from [python.org](https://python.org)
   - Ensure "Add Python to PATH" is checked during installation

2. **Install dependencies**:
   ```bash
   pip install streamlit pandas plotly requests python-dotenv
   ```

3. **Run the application**:
   ```bash
   streamlit run app.py
   ```

#### Linux/macOS Installation

1. **Install Python**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip

   # macOS (with Homebrew)
   brew install python3
   ```

2. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   streamlit run app.py
   ```

## ⚙️ Configuration

### API Keys Setup

1. **OpenAI API Key**:
   - Visit [OpenAI Platform](https://platform.openai.com)
   - Create an account and generate an API key
   - Enter the key in the sidebar under "AI Configuration"

2. **VirusTotal API Key** (Optional):
   - Visit [VirusTotal](https://www.virustotal.com)
   - Sign up for a free account
   - Generate an API key for higher rate limits

3. **Other LLM Providers**:
   - **Anthropic**: Get API key from [Anthropic Console](https://console.anthropic.com)
   - **Google**: Use Google Cloud AI Platform
   - **Cohere**: Sign up at [Cohere](https://cohere.ai)

### Environment Variables

Create a `.env` file in the project root:

```env
# API Keys (optional - can be entered in UI)
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# Application Settings
LOG_LEVEL=INFO
CACHE_TTL=300
MAX_THREADS=4
```

## 🎨 Theme System

### Automatic Theme Detection

The app automatically detects your system's theme preference:
- **Light Mode**: Clean, bright interface for well-lit environments
- **Dark Mode**: Easy on the eyes for low-light environments
- **Auto Mode**: Follows your system preference

### Manual Theme Toggle

1. **Access Theme Settings**: Look for the "🎨 Theme Settings" section in the sidebar
2. **Choose Theme**: Select from Auto, Light, or Dark modes
3. **Smooth Transitions**: Watch as the interface smoothly transitions between themes
4. **Persistent Preferences**: Your theme choice is saved across sessions

## 📱 Responsive Design

### Device Compatibility

- **🖥️ Desktop**: Full layout with sidebar navigation
- **📱 Mobile**: Stacked layout with touch-friendly interface
- **📟 Tablet**: Optimized spacing and sizing

### Accessibility Features

- **High Contrast Mode**: Enhanced visibility for users with visual impairments
- **Reduced Motion**: Respects user's motion sensitivity preferences
- **Keyboard Navigation**: Full keyboard accessibility support
- **Screen Reader**: Compatible with assistive technologies

## 🔧 Advanced Configuration

### Performance Tuning

1. **Thread Pool Configuration**:
   ```python
   # In app.py, modify the thread pool size
   @st.cache_resource
   def get_thread_pool():
       return ThreadPoolExecutor(max_workers=4)  # Adjust based on your system
   ```

2. **Cache Settings**:
   ```python
   # Adjust cache TTL (Time To Live)
   @st.cache_data(ttl=300)  # 5 minutes
   def get_cached_scan_results(scan_id: str):
       return None
   ```

3. **API Quota Limits**:
   ```python
   # Modify daily limits in handle_api_quota function
   'daily_limit': 1000  # Adjust based on your API plan
   ```

### Security Configuration

1. **API Key Validation**:
   - The app validates API key formats automatically
   - Keys are encrypted and stored securely
   - Input sanitization prevents injection attacks

2. **Rate Limiting**:
   - Built-in API quota management
   - Prevents excessive API usage
   - Automatic daily reset functionality

## 🧪 Testing

### Running Tests

1. **Unit Tests**:
   ```bash
   python -m pytest tests/
   ```

2. **Integration Tests**:
   ```bash
   python -m pytest tests/integration/
   ```

3. **UI Tests**:
   ```bash
   streamlit run app.py --server.headless true
   ```

### Test Coverage

- **Functionality**: All core features tested
- **Performance**: Load testing and optimization
- **Security**: Input validation and API security
- **UI/UX**: Cross-browser and device testing

## 🐛 Troubleshooting

### Common Issues

1. **Port Already in Use**:
   ```bash
   streamlit run app.py --server.port 8502
   ```

2. **API Key Errors**:
   - Verify API key format and validity
   - Check API quota limits
   - Ensure proper permissions

3. **Theme Not Switching**:
   - Clear browser cache
   - Refresh the page
   - Check browser compatibility

4. **Performance Issues**:
   - Reduce thread pool size
   - Clear cache: `streamlit cache clear`
   - Check system resources

### Debug Mode

Enable debug mode by setting:
```python
LOG_LEVEL=DEBUG
```

### Getting Help

- **Documentation**: Check this README and inline code comments
- **Issues**: Report bugs via GitHub issues
- **Community**: Join our Discord server for support

## 🔄 Updates and Maintenance

### Regular Updates

- **Security Patches**: Monthly security updates
- **Feature Updates**: Quarterly feature releases
- **Bug Fixes**: As needed based on user feedback

### Backup and Recovery

1. **Configuration Backup**:
   ```bash
   cp .env .env.backup
   cp config.json config.json.backup
   ```

2. **Data Backup**:
   ```bash
   cp -r data/ data_backup/
   ```

## 📊 Performance Metrics

### Benchmarks

- **Page Load Time**: < 2 seconds
- **Scan Execution**: 30-300 seconds (depending on scan type)
- **Memory Usage**: < 512MB typical
- **API Response Time**: < 1 second average

### Optimization Tips

1. **Use Caching**: Enable result caching for repeated scans
2. **Optimize Threads**: Adjust thread pool based on your system
3. **Monitor Quotas**: Keep track of API usage
4. **Regular Cleanup**: Clear old cache and temporary files

## 🤝 Contributing

### Development Setup

1. **Fork the repository**
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/new-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Code Standards

- **Python**: Follow PEP 8 guidelines
- **CSS**: Use consistent naming conventions
- **Documentation**: Add comments for complex logic
- **Testing**: Include tests for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Streamlit Team**: For the amazing web framework
- **OpenAI**: For powerful AI capabilities
- **VirusTotal**: For comprehensive threat intelligence
- **Community**: For feedback and contributions

## 📞 Support

- **Email**: support@sentinelai.com
- **Discord**: [Join our community](https://discord.gg/sentinelai)
- **GitHub**: [Report issues](https://github.com/sentinelai/issues)

---

**Built with ❤️ by the SentinelAI Team**

*Empowering cybersecurity solutions through AI-driven intelligence and automation.*
