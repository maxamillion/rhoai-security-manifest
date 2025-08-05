# OpenShift AI Security Manifest Tool
## Product Requirements Document

### 1. Executive Summary

The OpenShift AI Security Manifest Tool is a command-line utility designed to generate comprehensive security reports for Red Hat OpenShift AI product releases. The tool provides DevOps engineers with detailed vulnerability assessments, security grading, and historical tracking capabilities to support both compliance reporting and proactive vulnerability management.

### 2. Product Overview

**Product Name:** OpenShift AI Security Manifest Tool  
**Version:** 1.0  
**Target Users:** DevOps Engineers, Security Analysts  
**Primary Use Cases:** Compliance reporting, Vulnerability assessment  

### 3. Technical Architecture

**Core Technology Stack:**
- **Language:** Python 3.9+
- **CLI Framework:** Click
- **TUI Framework:** Textual (for interactive modes)
- **Package Manager:** uv
- **Database:** SQLite (for persistent data and caching)
- **Build System:** Makefile

**Development Tooling:**
- Linting: ruff, mypy
- Testing: pytest, pytest-cov
- Security: bandit, safety
- Formatting: black, isort

**Python Package**
- Name: rhoai_security_manifest
- Version: 1.0

### 4. Functional Requirements

#### 4.1 Core Features

**F1: Release-Specific Manifest Generation**
- Accept OpenShift AI release version as input parameter
- Query Red Hat Container Catalog API for complete container inventory
- Generate holistic view of all containers in the specified release
- Support both interactive selection and batch processing modes

**F2: Container Security Analysis**
- Retrieve CVE data for each container image
- Fetch Red Hat Errata information
- Generate security analysis comparable to grype utility output
- Support package-level vulnerability details (optional via CLI flag)

**F3: Security Grading System**
- Assign letter grades (A, B, C, D, F) to each container image
- Prioritize Red Hat API security grades when available
- Implement fallback algorithm using:
  - CVE severity distribution (Critical, High, Medium, Low)
  - CVSS scores
  - Patch availability status
  - Age of vulnerabilities
  - Number of unpatched vulnerabilities

**F4: Historical Tracking**
- Track security posture changes between releases
- Highlight newly introduced vulnerabilities
- Identify resolved vulnerabilities from previous releases
- Maintain historical data for trend analysis

**F5: Multi-Format Output**
- JSON: Machine-readable structured data
- CSV: Spreadsheet-compatible tabular format
- HTML: Rich web-based report with interactive elements
- Markdown: Documentation-friendly format

#### 4.2 Data Management

**F6: Persistent Data Storage**
- SQLite database for caching API responses
- 180-day data retention policy
- Offline query capabilities using cached data
- Automatic cache invalidation and refresh mechanisms

**F7: API Integration**
- Red Hat Container Catalog API integration
- Red Hat Security Data API (CSAF) integration
- Graceful handling of API rate limits and failures
- Retry mechanisms with exponential backoff

#### 4.3 Command Line Interface

**Primary Commands:**
```bash
# Generate manifest for specific release
osai-security-manifest generate --release 2.8.0 --format json

# Include package-level details
osai-security-manifest generate --release 2.8.0 --packages --format html

# Compare releases
osai-security-manifest compare --from 2.7.0 --to 2.8.0

# Cache management
osai-security-manifest cache --clean --older-than 30d

# Interactive mode
osai-security-manifest interactive
```

### 5. Non-Functional Requirements

#### 5.1 Performance
- Generate complete manifest within 2 minutes for ~100 container images
- Support concurrent API requests with configurable limits
- Efficient database queries with proper indexing
- Memory usage optimization for large datasets

#### 5.2 Reliability
- Graceful degradation when APIs are unavailable
- Comprehensive error handling and logging
- Data validation for all API responses
- Recovery mechanisms for partial failures

#### 5.3 Security
- Secure coding practices throughout development
- Input validation and sanitization
- SQL injection prevention
- Secure handling of temporary files
- No sensitive data persistence

#### 5.4 Usability
- Clear, actionable error messages
- Progressive disclosure of information
- Intuitive command structure
- Comprehensive help documentation
- Colorized output for better readability

#### 5.5 Maintainability
- Modular architecture with clear separation of concerns
- Comprehensive test coverage (>90%)
- Type hints throughout codebase
- Detailed inline documentation
- Automated code quality checks

### 6. API Requirements

#### 6.1 Red Hat Container Catalog API
- **Endpoint:** `https://catalog.redhat.com/api/containers/v1/`
- **Purpose:** Container image discovery and metadata
- **Authentication:** None required
- **Rate Limiting:** Handle potential limits gracefully

#### 6.2 Red Hat Security Data API
- **Endpoint:** Red Hat Security Data API (CSAF)
- **Purpose:** CVE and security advisory data
- **Authentication:** None required
- **Data Format:** CSAF JSON format

### 7. Data Model

#### 7.1 Database Schema

**releases table:**
- id (INTEGER PRIMARY KEY)
- version (TEXT UNIQUE)
- created_at (TIMESTAMP)
- container_count (INTEGER)
- last_updated (TIMESTAMP)

**containers table:**
- id (INTEGER PRIMARY KEY)
- release_id (INTEGER FOREIGN KEY)
- name (TEXT)
- registry_url (TEXT)
- digest (TEXT)
- security_grade (TEXT)
- created_at (TIMESTAMP)
- last_scanned (TIMESTAMP)

**vulnerabilities table:**
- id (INTEGER PRIMARY KEY)
- container_id (INTEGER FOREIGN KEY)
- cve_id (TEXT)
- severity (TEXT)
- cvss_score (REAL)
- description (TEXT)
- fixed_in_version (TEXT)
- first_seen (TIMESTAMP)
- status (TEXT) -- 'new', 'existing', 'resolved'

**packages table:**
- id (INTEGER PRIMARY KEY)
- container_id (INTEGER FOREIGN KEY)
- name (TEXT)
- version (TEXT)
- vulnerability_count (INTEGER)

### 8. Security Grading Algorithm

#### 8.1 Grading Criteria (when Red Hat grade unavailable)

**Grade A (90-100 points):**
- No Critical or High severity vulnerabilities
- Minimal Medium severity issues
- All vulnerabilities have available patches

**Grade B (80-89 points):**
- No Critical vulnerabilities
- Limited High severity vulnerabilities with patches
- Reasonable Medium/Low vulnerability count

**Grade C (70-79 points):**
- Few Critical vulnerabilities with patches available
- Moderate High severity vulnerability count
- Acceptable overall security posture

**Grade D (60-69 points):**
- Multiple Critical vulnerabilities
- High count of unpatched vulnerabilities
- Concerning security posture requiring attention

**Grade F (0-59 points):**
- Numerous Critical vulnerabilities
- Many unpatched security issues
- Unacceptable security risk

#### 8.2 Scoring Formula
```
Score = 100 - (Critical * 20) - (High * 10) - (Medium * 5) - (Low * 1)
      - (Unpatched_Critical * 10) - (Age_Factor * 5)
```

### 9. Output Specifications

#### 9.1 Report Structure
1. **Executive Summary**
   - Overall security posture
   - Key metrics and trends
   - Critical issues requiring immediate attention

2. **Release Overview**
   - Container inventory
   - Security grade distribution
   - Comparison with previous release (if available)

3. **Container Analysis**
   - Individual container security reports
   - Vulnerability details
   - Package-level information (when requested)

4. **Historical Tracking**
   - Newly introduced vulnerabilities
   - Resolved vulnerabilities
   - Trend analysis

#### 9.2 Format-Specific Features

**HTML Report:**
- Interactive tables with sorting/filtering
- Expandable sections for detailed information
- Charts and graphs for visual representation
- Responsive design for various screen sizes

**JSON Output:**
- Structured data suitable for API consumption
- Complete dataset including metadata
- Consistent schema versioning

### 10. Quality Assurance

#### 10.1 Testing Strategy
- **Unit Tests:** Individual component testing (>90% coverage)
- **Integration Tests:** API integration and database operations
- **End-to-End Tests:** Complete workflow validation
- **Performance Tests:** Load testing with large datasets
- **Security Tests:** Vulnerability scanning and code analysis

#### 10.2 Code Quality
- **Static Analysis:** mypy, ruff, bandit
- **Security Scanning:** safety, semgrep
- **Code Formatting:** black, isort
- **Documentation:** Comprehensive docstrings and README

### 11. Deployment and Distribution

#### 11.1 Installation Methods
- PyPI package distribution
- Docker container option
- Standalone executable for offline environments

#### 11.2 Configuration Management
- Environment-based configuration
- Configuration file support
- CLI parameter overrides

### 12. Future Enhancements

#### 12.1 Planned Features (v2.0+)
- Integration with CI/CD pipelines
- Real-time vulnerability monitoring
- Custom security policy definitions
- Multi-tenant support
- REST API for programmatic access
- Advanced visualization and dashboards
- Export to SPDX/CycloneDX formats

#### 12.2 Integration Opportunities
- JIRA/GitHub issue creation for critical vulnerabilities
- Slack/Teams notifications
- Integration with security tools (Splunk, ELK stack)
- Policy-as-Code frameworks

### 13. Success Metrics

#### 13.1 Technical Metrics
- Report generation time < 2 minutes
- API response success rate > 99%
- Data accuracy validation
- Zero security vulnerabilities in tool itself

#### 13.2 User Experience Metrics
- Time to first successful report
- User adoption rate
- Feature utilization statistics
- User feedback scores

### 14. Risk Assessment

#### 14.1 Technical Risks
- **API Availability:** Red Hat API downtime or changes
- **Data Volume:** Scaling issues with large releases  
- **Performance:** Query optimization challenges

#### 14.2 Mitigation Strategies
- Robust caching and offline capabilities
- Comprehensive error handling
- Performance monitoring and optimization
- Regular API endpoint validation

### 15. Acceptance Criteria

The product will be considered complete when:

1. ✅ Successfully generates security manifests for OpenShift AI releases
2. ✅ Provides accurate security grading for all container images
3. ✅ Supports all specified output formats
4. ✅ Implements historical tracking and comparison features
5. ✅ Maintains 180-day data retention with offline capabilities
6. ✅ Achieves target performance benchmarks
7. ✅ Passes comprehensive security and quality audits
8. ✅ Includes complete documentation and examples

---

*This PRD serves as the foundational document for the OpenShift AI Security Manifest Tool development. Regular updates will be made as requirements evolve and user feedback is incorporated.*
