# SentraOS: Smart Operations & Security Platform

## Overview

SentraOS is a Python-based security monitoring and operations platform that provides real-time system monitoring, automated security scanning, and intelligent alerting through a web-based dashboard. The platform combines system performance tracking with network security capabilities, enabling proactive monitoring and threat detection.

The application uses a modular architecture with distinct components for monitoring, security scanning, automation, and web presentation. Data persistence is handled through SQLite, and the web interface provides real-time visualizations of system health and security status.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Application Structure

The platform follows a modular monolithic architecture with four primary modules:

1. **Network Monitor Module** (`network_monitor/`): Handles system metrics collection using psutil for CPU, memory, disk, and network statistics
2. **Security Scanner Module** (`security_scanner/`): Performs network security scanning using python-nmap to detect open ports and potential vulnerabilities
3. **Automation Module** (`automation/`): Manages scheduled tasks and automated responses using APScheduler for periodic monitoring and alerting
4. **Dashboard Module** (`dashboard/`): Provides a Flask-based web interface with real-time data visualization

**Rationale**: Modular separation allows independent development and testing of each component while maintaining clear boundaries of responsibility. This structure supports easy extension of functionality without affecting other modules.

### Frontend Architecture

The web interface uses server-side rendering with Flask templates and client-side JavaScript for dynamic updates:

- **Template Engine**: Jinja2 (Flask default) for HTML rendering
- **Styling**: Bootstrap 5 for responsive UI components
- **Visualization**: Chart.js for real-time performance graphs
- **Communication**: Vanilla JavaScript with fetch API for AJAX requests

**Rationale**: This approach balances simplicity with functionality. Bootstrap provides professional UI components without custom CSS overhead, while Chart.js offers robust visualization capabilities. Avoiding heavy frontend frameworks keeps the codebase lightweight and maintainable.

### Backend Architecture

Python-based backend using Flask as the web framework:

- **Web Framework**: Flask with Flask-CORS for API endpoints
- **ORM**: SQLAlchemy for database abstraction
- **Session Management**: Flask built-in session handling
- **Task Scheduling**: APScheduler (BackgroundScheduler) for periodic jobs

**Design Pattern**: The application uses a service-oriented pattern where each module exposes specific functionality through class interfaces (SystemMonitor, SecurityScanner, AutoResponder).

**Rationale**: Flask's lightweight nature and flexibility make it ideal for this monitoring platform. SQLAlchemy provides database portability and type safety. APScheduler enables reliable background task execution without requiring external job queues.

### Data Storage

SQLite database with SQLAlchemy ORM:

- **Database**: SQLite (`sentra.db`) for metrics, scan results, and alerts
- **Models**: Three primary tables defined in `models.py`:
  - `system_metrics`: Stores CPU, memory, disk, and network measurements
  - `scan_results`: Stores security scan outcomes with vulnerability data
  - `alerts`: Stores performance and security alerts with acknowledgment tracking

**Schema Design**:
- JSON columns for flexible storage of nested data (port details, vulnerability info)
- Timestamp fields for temporal queries and historical analysis
- Severity/risk level fields for alert prioritization

**Rationale**: SQLite eliminates external database dependencies while providing full SQL capabilities. JSON columns offer schema flexibility for varying security scan outputs without requiring complex relational structures. This design supports rapid development and easy deployment.

### Monitoring & Data Collection

Real-time system monitoring architecture:

- **Metrics Collection**: psutil library for cross-platform system statistics
- **Collection Interval**: Configurable periodic checks via APScheduler
- **Performance Thresholds**: Hardcoded alert thresholds (80% CPU, 85% memory)
- **Network Baseline**: Tracks network I/O deltas from initial baseline

**Rationale**: psutil provides reliable, cross-platform system metrics without requiring privileged access for basic monitoring. Periodic collection with APScheduler avoids constant polling overhead while maintaining reasonable update frequency.

### Security Scanning

Network security scanning using nmap:

- **Scanner**: python-nmap wrapper for nmap command-line tool
- **Scan Type**: TCP SYN scans with fallback to TCP connect
- **Port Range**: Default 1-1000 ports, configurable
- **Vulnerability Detection**: Service version detection for known vulnerability identification
- **Risk Assessment**: Automated risk level calculation based on open ports and services

**Rationale**: nmap is an industry-standard tool with comprehensive scanning capabilities. The python-nmap wrapper provides programmatic access while maintaining nmap's reliability. Service detection enables vulnerability correlation against known CVE databases.

### Alert & Response System

Intelligent alerting with the AutoResponder class:

- **Alert Storage**: In-memory list with configurable maximum size (100 alerts)
- **Alert Types**: Performance alerts (CPU/memory thresholds) and security alerts (scan findings)
- **Severity Levels**: Low, medium, high classification
- **Acknowledgment**: Boolean flag for alert lifecycle management

**Rationale**: In-memory alert storage provides fast access for dashboard display. The 100-alert limit prevents unbounded memory growth. Acknowledgment tracking enables alert lifecycle management without requiring immediate resolution.

### API & Data Flow

RESTful API endpoints serve the dashboard:

- **Metrics Endpoint**: Returns current system metrics as JSON
- **Scan Endpoint**: Triggers security scans and returns results
- **Alerts Endpoint**: Retrieves active alerts with filtering
- **Real-time Updates**: Client polls endpoints at regular intervals

**Rationale**: REST API design separates data collection from presentation, enabling potential future integrations with other clients or services. Polling architecture is simpler than WebSockets while providing adequate real-time updates for monitoring use cases.

## External Dependencies

### Core Python Libraries

- **Flask**: Web framework for dashboard and API endpoints
- **SQLAlchemy**: ORM for database operations and model definitions
- **psutil**: Cross-platform system and process monitoring
- **python-nmap**: Python wrapper for nmap security scanning
- **APScheduler**: Background task scheduling for automation
- **Flask-CORS**: Cross-origin resource sharing support

### Frontend Libraries (CDN)

- **Bootstrap 5**: CSS framework for responsive UI components
- **Font Awesome 6**: Icon library for visual indicators
- **Chart.js**: JavaScript charting library for data visualization

### System Requirements

- **Python 3.11**: Runtime environment
- **nmap**: Command-line tool required by python-nmap (must be installed separately)
- **SQLite**: Database engine (included with Python)

### Environment Configuration

- **SESSION_SECRET**: Environment variable for Flask session encryption (defaults to development key)
- **Database Path**: Hardcoded to `sentra.db` in project root

**Note**: The application currently has no external API integrations or cloud service dependencies. All functionality operates locally or within the deployment environment.