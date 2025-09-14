# SentinelAI v2 - Docker Deployment Guide

This guide provides comprehensive instructions for deploying SentinelAI v2 using Docker containers.

## 🐳 Quick Start

### Prerequisites
- Docker Engine 20.10+ 
- Docker Compose 2.0+
- At least 4GB RAM available
- 10GB free disk space

### 1. Clone and Build
```bash
git clone <repository-url>
cd sentinelai-v2
```

### 2. Production Deployment
```bash
# Build and start production environment
./scripts/docker-build.sh build-prod
./scripts/docker-build.sh start-prod

# Or on Windows
scripts\docker-build.bat build-prod
scripts\docker-build.bat start-prod
```

### 3. Access Application
- **Web Interface**: http://localhost:8501
- **Health Check**: http://localhost:8501/_stcore/health

## 🏗️ Architecture

### Multi-Stage Dockerfile
- **Stage 1 (base)**: Python 3.11 + system dependencies
- **Stage 2 (python-deps)**: Python package installation
- **Stage 3 (app)**: Application code + non-root user
- **Stage 4 (production)**: Optimized production image

### Services
- **sentinelai**: Main application (Streamlit)
- **clamav**: Antivirus engine for malware detection
- **redis**: Caching layer (optional)
- **nginx**: Reverse proxy with SSL (optional)

## 📋 Available Commands

### Build Commands
```bash
# Production build
./scripts/docker-build.sh build-prod

# Development build
./scripts/docker-build.sh build-dev
```

### Runtime Commands
```bash
# Start production
./scripts/docker-build.sh start-prod

# Start development (with hot reloading)
./scripts/docker-build.sh start-dev

# Stop all containers
./scripts/docker-build.sh stop

# Restart containers
./scripts/docker-build.sh restart
```

### Monitoring Commands
```bash
# View logs
./scripts/docker-build.sh logs
./scripts/docker-build.sh logs clamav

# Check status
./scripts/docker-build.sh status

# Cleanup resources
./scripts/docker-build.sh cleanup
```

## 🔧 Configuration

### Environment Variables
```yaml
# docker-compose.yml
environment:
  - PYTHONPATH=/app
  - STREAMLIT_SERVER_PORT=8501
  - STREAMLIT_SERVER_ADDRESS=0.0.0.0
  - STREAMLIT_SERVER_HEADLESS=true
```

### Volume Mounts
```yaml
volumes:
  - sentinelai_data:/app/data      # Application data
  - sentinelai_logs:/app/logs      # Log files
  - sentinelai_reports:/app/reports # Generated reports
  - sentinelai_cache:/app/cache    # Cache files
  - sentinelai_config:/app/config  # Configuration
```

### Host Directory Scanning
```yaml
volumes:
  - /var/log:/host/var/log:ro      # Read-only host logs
  - /tmp:/host/tmp:ro              # Read-only temp directory
```

## 🔒 Security Features

### Container Security
- **Non-root user**: Application runs as `sentinelai` user
- **Read-only filesystem**: Where possible
- **Minimal base image**: Python slim variant
- **Security headers**: Nginx configuration includes security headers

### Network Security
- **Internal networks**: Services communicate via private networks
- **Port exposure**: Only necessary ports exposed
- **SSL termination**: Nginx handles SSL/TLS

### Data Protection
- **Encrypted volumes**: All data volumes are encrypted at rest
- **Backup support**: Built-in backup/restore functionality
- **Access controls**: Proper file permissions

## 📊 Monitoring & Logging

### Health Checks
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8501/_stcore/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Log Management
- **Centralized logging**: All services log to stdout
- **Log rotation**: Handled by Docker
- **Log levels**: Configurable per service

### Resource Monitoring
```bash
# View resource usage
docker stats

# Container status
docker-compose ps
```

## 🚀 Production Deployment

### 1. SSL Configuration
```bash
# Create SSL directory
mkdir ssl

# Copy your certificates
cp your-cert.pem ssl/cert.pem
cp your-key.pem ssl/key.pem
```

### 2. Environment Configuration
```bash
# Create production environment file
cat > .env.production << EOF
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_SERVER_HEADLESS=true
EOF
```

### 3. Start Production Stack
```bash
# Start with Nginx
docker-compose up -d

# Verify all services
docker-compose ps
```

### 4. Backup Configuration
```bash
# Create backup
./scripts/docker-build.sh backup

# Restore from backup
./scripts/docker-build.sh restore backup_20231201_120000
```

## 🛠️ Development

### Development Environment
```bash
# Start development with hot reloading
./scripts/docker-build.sh start-dev

# View development logs
./scripts/docker-build.sh logs sentinelai-dev
```

### Code Changes
- **Hot reloading**: Enabled in development mode
- **Volume mounts**: Source code mounted for live updates
- **Debug port**: Available on port 5678

### Testing
```bash
# Run tests in container
docker-compose -f docker-compose.dev.yml exec sentinelai-dev python -m pytest

# Interactive shell
docker-compose -f docker-compose.dev.yml exec sentinelai-dev bash
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Check what's using the port
netstat -tulpn | grep :8501

# Kill the process
sudo kill -9 <PID>
```

#### 2. Permission Issues
```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./data
```

#### 3. ClamAV Database Issues
```bash
# Update ClamAV database
docker-compose exec clamav freshclam

# Restart ClamAV
docker-compose restart clamav
```

#### 4. Memory Issues
```bash
# Increase Docker memory limit
# In Docker Desktop: Settings > Resources > Memory
```

### Debug Commands
```bash
# Container logs
docker-compose logs -f sentinelai

# Container shell
docker-compose exec sentinelai bash

# Resource usage
docker stats

# System information
docker system df
```

## 📈 Performance Optimization

### Resource Limits
```yaml
# docker-compose.yml
services:
  sentinelai:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'
```

### Caching
- **Redis**: Enabled for application caching
- **Docker layers**: Optimized build process
- **Volume caching**: Persistent data volumes

### Scaling
```bash
# Scale application
docker-compose up -d --scale sentinelai=3

# Load balancer configuration needed
```

## 🔄 Updates & Maintenance

### Application Updates
```bash
# Pull latest changes
git pull

# Rebuild and restart
./scripts/docker-build.sh build-prod
./scripts/docker-build.sh restart
```

### Database Updates
```bash
# Update ClamAV
docker-compose exec clamav freshclam

# Restart services
docker-compose restart
```

### Cleanup
```bash
# Remove unused resources
./scripts/docker-build.sh cleanup

# Remove old images
docker image prune -a
```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Streamlit Deployment](https://docs.streamlit.io/deploy)
- [ClamAV Documentation](https://docs.clamav.net/)

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review Docker logs
3. Check GitHub issues
4. Contact support team


