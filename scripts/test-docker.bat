@echo off
REM SentinelAI v2 - Docker Test Script for Windows
REM Tests Docker setup and basic functionality

setlocal enabledelayedexpansion

REM Colors (Windows doesn't support colors in batch, but we can use echo)
set SUCCESS=✅
set ERROR=❌
set WARNING=⚠️
set INFO=ℹ️

:print_header
echo ================================
echo   SentinelAI v2 Docker Test
echo ================================
goto :eof

:print_success
echo %SUCCESS% %~1
goto :eof

:print_error
echo %ERROR% %~1
goto :eof

:print_info
echo %INFO% %~1
goto :eof

REM Test Docker installation
:test_docker
call :print_info "Testing Docker installation..."
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Docker is not installed or not in PATH"
    set /a failed_tests+=1
    goto :eof
)
for /f "tokens=*" %%i in ('docker --version') do set docker_version=%%i
call :print_success "Docker is installed: !docker_version!"
set /a passed_tests+=1
goto :eof

REM Test Docker Compose
:test_compose
call :print_info "Testing Docker Compose..."
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Docker Compose is not installed or not in PATH"
    set /a failed_tests+=1
    goto :eof
)
for /f "tokens=*" %%i in ('docker-compose --version') do set compose_version=%%i
call :print_success "Docker Compose is installed: !compose_version!"
set /a passed_tests+=1
goto :eof

REM Test Dockerfile syntax
:test_dockerfile
call :print_info "Testing Dockerfile syntax..."
docker build --dry-run -f Dockerfile . >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Dockerfile has syntax errors"
    set /a failed_tests+=1
    goto :eof
)
call :print_success "Dockerfile syntax is valid"
set /a passed_tests+=1
goto :eof

REM Test image build
:test_build
call :print_info "Testing image build..."
docker build -f Dockerfile -t sentinelai:test --target app . >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Failed to build Docker image"
    set /a failed_tests+=1
    goto :eof
)
call :print_success "Docker image built successfully"
set /a passed_tests+=1
goto :eof

REM Test container startup
:test_container
call :print_info "Testing container startup..."

REM Start container
for /f "tokens=*" %%i in ('docker run -d -p 8501:8501 sentinelai:test') do set container_id=%%i

REM Wait for startup
timeout /t 10 /nobreak >nul

REM Test health check
curl -f http://localhost:8501/_stcore/health >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Container health check failed"
    docker logs !container_id!
    docker stop !container_id! >nul 2>&1
    set /a failed_tests+=1
    goto :eof
)

call :print_success "Container started and health check passed"

REM Cleanup
docker stop !container_id! >nul 2>&1
docker rm !container_id! >nul 2>&1
set /a passed_tests+=1
goto :eof

REM Test compose file
:test_compose_file
call :print_info "Testing docker-compose.yml syntax..."
docker-compose -f docker-compose.yml config >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "docker-compose.yml has syntax errors"
    set /a failed_tests+=1
    goto :eof
)
call :print_success "docker-compose.yml syntax is valid"
set /a passed_tests+=1
goto :eof

REM Test volume creation
:test_volumes
call :print_info "Testing volume creation..."
docker-compose -f docker-compose.yml up -d --no-deps sentinelai
timeout /t 5 /nobreak >nul

REM Check if volumes exist
docker volume ls | findstr sentinelai >nul
if %errorlevel% neq 0 (
    call :print_error "Failed to create volumes"
    docker-compose -f docker-compose.yml down
    set /a failed_tests+=1
    goto :eof
)

call :print_success "Volumes created successfully"

REM Cleanup
docker-compose -f docker-compose.yml down
set /a passed_tests+=1
goto :eof

REM Main test function
:main
call :print_header

set passed_tests=0
set failed_tests=0

call :test_docker
call :test_compose
call :test_dockerfile
call :test_build
call :test_container
call :test_compose_file
call :test_volumes

echo ==================================
echo Test Results: !passed_tests!/7 passed
echo ==================================

if !passed_tests! equ 7 (
    call :print_success "All tests passed! Docker setup is ready."
    exit /b 0
) else (
    call :print_error "Some tests failed. Please check the errors above."
    exit /b 1
)

REM Run main function
call :main


