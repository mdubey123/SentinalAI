# SentinelAI v2 - Docker Deployment Guide

## 🐳 Updated Docker Configuration

This guide covers the updated Docker setup for SentinelAI v2 with comprehensive LLM provider support and enhanced functionality.

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM
- 10GB free disk space

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd SentinelAI
```

### 2. Configure Environment Variables

Copy the example environment file and configure your API keys:

```bash
cp docker.env.example .env
```

Edit `.env` file with your API keys:

```bash
# LLM Provider API Keys (optional - can also be set via UI)
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
GROQ_API_KEY=your_groq_api_key_here
COHERE_API_KEY=your_cohere_api_key_here
HUGGINGFACE_API_KEY=your_huggingface_api_key_here
MISTRAL_API_KEY=your_mistral_api_key_here
LLAMA_API_KEY=your_llama_api_key_here

# Security Services
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### 3. Run the Application

#### Production Mode
```bash
docker-compose up -d
```

#### Development Mode
```bash
docker-compose -f docker-compose.dev.yml up -d
```

### 4. Access the Application

Open your browser and navigate to:
- **Application**: http://localhost:8501
- **Nginx (if enabled)**: http://localhost:80

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key | - | No* |
| `ANTHROPIC_API_KEY` | Anthropic API key | - | No* |
| `GOOGLE_API_KEY` | Google API key | - | No* |
| `GROQ_API_KEY` | Groq API key | - | No* |
| `COHERE_API_KEY` | Cohere API key | - | No* |
| `HUGGINGFACE_API_KEY` | Hugging Face API key | - | No* |
| `MISTRAL_API_KEY` | Mistral API key | - | No* |
| `LLAMA_API_KEY` | Llama API key | - | No* |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | - | No* |
| `SENTINELAI_ENV` | Environment mode | production | No |
| `LOG_LEVEL` | Logging level | INFO | No |

*API keys can be set via the application UI instead of environment variables.

### Supported LLM Providers

The application now supports 9 major LLM providers with 100+ models:

#### OpenAI
- GPT-5 Series: `gpt-5`, `gpt-5-pro`, `gpt-5-mini`
- GPT-4 Series: `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `gpt-4`
- o Series: `o3-pro`, `o3`, `o3-mini`, `o4-mini`
- GPT-3.5 Series: `gpt-3.5-turbo`
- Codex Series: `codex`

#### Anthropic
- `claude-3.5-sonnet`, `claude-3-opus`, `claude-3-sonnet`, `claude-3-haiku`
- `claude-2.1`, `claude-2.0`, `claude-instant`

#### Google Gemini
- Gemini 2.5 Series: `gemini-2.5-pro-diamond`, `gemini-2.5-pro`, `gemini-2.5-flash-spark`
- Gemini 2.0 Series: `gemini-2.0-pro`, `gemini-2.0-flash`, `gemini-2.0-flash-lite`
- Gemini 1.5 Series: `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-1.5-flash-lite`
- Specialized Models: `gemini-nano-banana`, `gemini-veo-3`, `gemini-robotics`

#### Groq
- Production Models: `llama-3.1-8b`, `llama-3.3-70b`, `llama-guard-4-12b`
- Groq-Optimized: `compound`, `compound-mini`
- Tool-Use Models: `llama-3-groq-70b-tool-use`, `llama-3-groq-8b-tool-use`

#### Additional Providers
- **Cohere**: `command-r-plus`, `command-r`, `command`, `command-light`
- **Hugging Face**: `mistral-7b`, `llama-2-7b`, `code-llama`, `falcon-7b`
- **Mistral**: `mistral-large`, `mistral-medium`, `mixtral-8x7b`
- **Llama**: `llama-3.1-8b`, `llama-3-8b`, `llama-2-7b`
- **Local**: `local-model`, `ollama-llama3`, `ollama-mistral`

## 🏗️ Docker Architecture

### Services

1. **sentinelai**: Main application container
2. **clamav**: Antivirus scanning engine
3. **redis**: Caching service (optional)
4. **nginx**: Reverse proxy (optional)

### Volumes

- `sentinelai_data`: Application data
- `sentinelai_logs`: Application logs
- `sentinelai_reports`: Generated reports
- `sentinelai_cache`: LLM and scan cache
- `sentinelai_config`: Configuration files
- `clamav_data`: ClamAV virus definitions

### Networks

- `sentinelai-network`: Internal communication
- `sentinelai-dev-network`: Development environment

## 🔍 Features

### Enhanced LLM Integration
- **Universal LLM Client**: Works with all supported providers
- **Real-time Testing**: Test LLM connections before use
- **Secure API Management**: Encrypted storage and validation
- **Fallback Support**: Graceful degradation when LLM unavailable
- **Enhanced Analysis**: AI-powered threat intelligence

### Security Features
- **Multi-Agent Architecture**: Specialized security agents
- **Malware Detection**: YARA rules and ClamAV integration
- **Vulnerability Assessment**: VAPT scanning capabilities
- **Threat Intelligence**: AI-powered analysis and reporting

### UI/UX Improvements
- **Modern Dark Theme**: Professional cybersecurity interface
- **Responsive Design**: Works on all devices
- **Theme Toggle**: Light/Dark mode switching
- **Enhanced Text Display**: Fixed text truncation issues
- **No Search in Selectboxes**: Clean, simple dropdown selection

## 🛠️ Development

### Development Mode

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f sentinelai-dev

# Stop development environment
docker-compose -f docker-compose.dev.yml down
```

### Building Custom Images

```bash
# Build production image
docker-compose build sentinelai

# Build development image
docker-compose -f docker-compose.dev.yml build sentinelai-dev
```

## 📊 Monitoring

### Health Checks

All services include health checks:

```bash
# Check service health
docker-compose ps

# View health check logs
docker inspect sentinelai-app | grep -A 10 Health
```

### Logs

```bash
# View application logs
docker-compose logs -f sentinelai

# View all service logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f clamav
```

## 🔧 Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Change ports in docker-compose.yml
   ports:
     - "8502:8501"  # Use different host port
   ```

2. **API Key Issues**
   - Set API keys via environment variables or UI
   - Check API key format and validity
   - Use the Settings page to test connections

3. **Memory Issues**
   ```bash
   # Increase Docker memory limit
   # Docker Desktop: Settings > Resources > Memory
   ```

4. **Permission Issues**
   ```bash
   # Fix volume permissions
   sudo chown -R 1000:1000 ./data ./logs ./reports
   ```

### Debug Mode

```bash
# Run with debug logging
docker-compose -f docker-compose.dev.yml up -d
docker-compose -f docker-compose.dev.yml exec sentinelai-dev bash
```

## 🔒 Security Considerations

- API keys are encrypted and stored securely
- Non-root user runs the application
- Network isolation between services
- Regular security updates via base images
- ClamAV virus definitions updated automatically

## 📈 Performance

### Optimization Tips

1. **Resource Allocation**
   - Minimum 4GB RAM recommended
   - SSD storage for better I/O performance
   - Multiple CPU cores for parallel processing

2. **Caching**
   - Redis caching enabled by default
   - LLM response caching
   - Scan result caching

3. **Network**
   - Use local networks for internal communication
   - Optimize API rate limits
   - Monitor bandwidth usage

## 🆘 Support

For issues and support:

1. Check the logs: `docker-compose logs -f`
2. Verify configuration: Review environment variables
3. Test LLM connections: Use Settings page
4. Check system resources: Monitor CPU/Memory usage

## 📝 Changelog

### v2.1.0 Updates
- ✅ Added comprehensive LLM provider support
- ✅ Enhanced Docker configuration
- ✅ Fixed text display issues
- ✅ Removed search functionality from selectboxes
- ✅ Added universal LLM client
- ✅ Improved security and performance
- ✅ Enhanced UI/UX with modern theme
- ✅ Added comprehensive documentation

---

**SentinelAI v2** - Advanced Cybersecurity Analysis Platform

