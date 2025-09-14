@echo off
REM SentinelAI v2 - Docker Build Script for Windows
REM Builds and manages Docker containers for SentinelAI

setlocal enabledelayedexpansion

REM Configuration
set IMAGE_NAME=sentinelai
set TAG=latest
set DOCKERFILE=Dockerfile
set COMPOSE_FILE=docker-compose.yml
set DEV_COMPOSE_FILE=docker-compose.dev.yml

REM Colors (Windows doesn't support colors in batch, but we can use echo)
set SUCCESS=✅
set ERROR=❌
set WARNING=⚠️
set INFO=ℹ️

REM Functions
:print_header
echo ================================
echo   SentinelAI v2 Docker Manager
echo ================================
goto :eof

:print_success
echo %SUCCESS% %~1
goto :eof

:print_error
echo %ERROR% %~1
goto :eof

:print_warning
echo %WARNING% %~1
goto :eof

:print_info
echo %INFO% %~1
goto :eof

REM Check if Docker is running
:check_docker
docker info >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Docker is not running. Please start Docker and try again."
    exit /b 1
)
call :print_success "Docker is running"
goto :eof

REM Build production image
:build_production
call :print_info "Building production image..."
docker build -f %DOCKERFILE% -t %IMAGE_NAME%:%TAG% --target production .
if %errorlevel% neq 0 (
    call :print_error "Failed to build production image"
    exit /b 1
)
call :print_success "Production image built successfully"
goto :eof

REM Build development image
:build_development
call :print_info "Building development image..."
docker build -f %DOCKERFILE% -t %IMAGE_NAME%:dev --target app .
if %errorlevel% neq 0 (
    call :print_error "Failed to build development image"
    exit /b 1
)
call :print_success "Development image built successfully"
goto :eof

REM Start production environment
:start_production
call :print_info "Starting production environment..."
docker-compose -f %COMPOSE_FILE% up -d
if %errorlevel% neq 0 (
    call :print_error "Failed to start production environment"
    exit /b 1
)
call :print_success "Production environment started"
call :print_info "Application available at: http://localhost:8501"
goto :eof

REM Start development environment
:start_development
call :print_info "Starting development environment..."
docker-compose -f %DEV_COMPOSE_FILE% up -d
if %errorlevel% neq 0 (
    call :print_error "Failed to start development environment"
    exit /b 1
)
call :print_success "Development environment started"
call :print_info "Application available at: http://localhost:8501"
call :print_info "Debug port available at: localhost:5678"
goto :eof

REM Stop all containers
:stop_all
call :print_info "Stopping all containers..."
docker-compose -f %COMPOSE_FILE% down
docker-compose -f %DEV_COMPOSE_FILE% down
call :print_success "All containers stopped"
goto :eof

REM Show logs
:show_logs
set service=%~1
if "%service%"=="" set service=sentinelai
call :print_info "Showing logs for %service%..."
docker-compose -f %COMPOSE_FILE% logs -f %service%
goto :eof

REM Show status
:show_status
call :print_info "Container status:"
docker-compose -f %COMPOSE_FILE% ps
echo.
call :print_info "Resource usage:"
docker stats --no-stream
goto :eof

REM Cleanup
:cleanup
call :print_info "Cleaning up Docker resources..."
docker system prune -f
docker volume prune -f
call :print_success "Cleanup completed"
goto :eof

REM Show help
:show_help
echo Usage: %0 [COMMAND]
echo.
echo Commands:
echo   build-prod     Build production image
echo   build-dev      Build development image
echo   start-prod     Start production environment
echo   start-dev      Start development environment
echo   stop           Stop all containers
echo   restart        Restart all containers
echo   logs [service] Show logs (default: sentinelai)
echo   status         Show container status
echo   cleanup        Clean up Docker resources
echo   help           Show this help message
echo.
echo Examples:
echo   %0 build-prod
echo   %0 start-dev
echo   %0 logs clamav
goto :eof

REM Main script
:main
call :print_header
call :check_docker
if %errorlevel% neq 0 exit /b 1

set command=%~1
if "%command%"=="" set command=help

if "%command%"=="build-prod" (
    call :build_production
) else if "%command%"=="build-dev" (
    call :build_development
) else if "%command%"=="start-prod" (
    call :start_production
) else if "%command%"=="start-dev" (
    call :start_development
) else if "%command%"=="stop" (
    call :stop_all
) else if "%command%"=="restart" (
    call :stop_all
    call :start_production
) else if "%command%"=="logs" (
    call :show_logs %2
) else if "%command%"=="status" (
    call :show_status
) else if "%command%"=="cleanup" (
    call :cleanup
) else (
    call :show_help
)

goto :eof

REM Run main function
call :main %*


