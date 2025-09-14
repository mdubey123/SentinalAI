#!/bin/bash
# SentinelAI v2 - Docker Test Script
# Tests Docker setup and basic functionality

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  SentinelAI v2 Docker Test     ${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Test Docker installation
test_docker() {
    print_info "Testing Docker installation..."
    if ! docker --version > /dev/null 2>&1; then
        print_error "Docker is not installed or not in PATH"
        return 1
    fi
    print_success "Docker is installed: $(docker --version)"
}

# Test Docker Compose
test_compose() {
    print_info "Testing Docker Compose..."
    if ! docker-compose --version > /dev/null 2>&1; then
        print_error "Docker Compose is not installed or not in PATH"
        return 1
    fi
    print_success "Docker Compose is installed: $(docker-compose --version)"
}

# Test Dockerfile syntax
test_dockerfile() {
    print_info "Testing Dockerfile syntax..."
    if ! docker build --dry-run -f Dockerfile . > /dev/null 2>&1; then
        print_error "Dockerfile has syntax errors"
        return 1
    fi
    print_success "Dockerfile syntax is valid"
}

# Test image build
test_build() {
    print_info "Testing image build..."
    if ! docker build -f Dockerfile -t sentinelai:test --target app . > /dev/null 2>&1; then
        print_error "Failed to build Docker image"
        return 1
    fi
    print_success "Docker image built successfully"
}

# Test container startup
test_container() {
    print_info "Testing container startup..."
    
    # Start container
    container_id=$(docker run -d -p 8501:8501 sentinelai:test)
    
    # Wait for startup
    sleep 10
    
    # Test health check
    if curl -f http://localhost:8501/_stcore/health > /dev/null 2>&1; then
        print_success "Container started and health check passed"
    else
        print_error "Container health check failed"
        docker logs $container_id
        docker stop $container_id > /dev/null 2>&1
        return 1
    fi
    
    # Cleanup
    docker stop $container_id > /dev/null 2>&1
    docker rm $container_id > /dev/null 2>&1
}

# Test compose file
test_compose_file() {
    print_info "Testing docker-compose.yml syntax..."
    if ! docker-compose -f docker-compose.yml config > /dev/null 2>&1; then
        print_error "docker-compose.yml has syntax errors"
        return 1
    fi
    print_success "docker-compose.yml syntax is valid"
}

# Test volume creation
test_volumes() {
    print_info "Testing volume creation..."
    docker-compose -f docker-compose.yml up -d --no-deps sentinelai
    sleep 5
    
    # Check if volumes exist
    if docker volume ls | grep -q sentinelai; then
        print_success "Volumes created successfully"
    else
        print_error "Failed to create volumes"
        docker-compose -f docker-compose.yml down
        return 1
    fi
    
    # Cleanup
    docker-compose -f docker-compose.yml down
}

# Main test function
main() {
    print_header
    
    local tests=(
        "test_docker"
        "test_compose"
        "test_dockerfile"
        "test_build"
        "test_container"
        "test_compose_file"
        "test_volumes"
    )
    
    local passed=0
    local total=${#tests[@]}
    
    for test in "${tests[@]}"; do
        if $test; then
            ((passed++))
        else
            print_error "Test $test failed"
        fi
        echo
    done
    
    echo "=================================="
    echo "Test Results: $passed/$total passed"
    echo "=================================="
    
    if [ $passed -eq $total ]; then
        print_success "All tests passed! Docker setup is ready."
        exit 0
    else
        print_error "Some tests failed. Please check the errors above."
        exit 1
    fi
}

# Run tests
main "$@"


