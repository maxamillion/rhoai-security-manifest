"""HTML report generator with enhanced templates."""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from jinja2 import Environment, BaseLoader

from ...utils.logging import get_logger

logger = get_logger("reports.generators.html")


class HTMLReportGenerator:
    """Generate HTML reports with interactive features."""
    
    def __init__(self):
        """Initialize the HTML report generator."""
        self.env = Environment(loader=BaseLoader())
        
        # Add custom filters
        self.env.filters['datetime'] = self._format_datetime
        self.env.filters['severity_color'] = self._get_severity_color
        self.env.filters['grade_color'] = self._get_grade_color
    
    def generate_report(self, report_data: Dict[str, Any], output_path: Path) -> None:
        """Generate comprehensive HTML security report.
        
        Args:
            report_data: Report data dictionary
            output_path: Output file path
        """
        logger.info(f"Generating HTML report: {output_path}")
        
        template = self.env.from_string(self._get_html_template())
        
        # Enhance report data with HTML-specific formatting
        enhanced_data = self._enhance_report_data(report_data)
        
        # Render template
        html_content = template.render(**enhanced_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated successfully: {output_path}")
    
    def _enhance_report_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance report data with HTML-specific information."""
        enhanced = report_data.copy()
        
        # Add severity totals
        severity_totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for container in enhanced["containers"]:
            vulns = container.get("vulnerabilities", {})
            for severity in severity_totals:
                severity_totals[severity] += vulns.get(severity, 0)
        
        enhanced["severity_totals"] = severity_totals
        
        # Add grade statistics
        grade_stats = {}
        for container in enhanced["containers"]:
            grade = container.get("security_grade", "Unknown")
            grade_stats[grade] = grade_stats.get(grade, 0) + 1
        
        enhanced["grade_stats"] = grade_stats
        
        # Sort containers by security score
        enhanced["containers"] = sorted(
            enhanced["containers"],
            key=lambda x: x.get("security_score", 0),
            reverse=True
        )
        
        return enhanced
    
    def _format_datetime(self, value: str) -> str:
        """Format datetime string for display."""
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, AttributeError):
            return value
    
    def _get_severity_color(self, severity: str) -> str:
        """Get CSS color class for vulnerability severity."""
        color_map = {
            "Critical": "danger",
            "High": "warning", 
            "Medium": "info",
            "Low": "secondary",
            "Unknown": "light"
        }
        return color_map.get(severity, "light")
    
    def _get_grade_color(self, grade: str) -> str:
        """Get CSS color class for security grade."""
        color_map = {
            "A": "success",
            "B": "info",
            "C": "warning",
            "D": "orange",
            "F": "danger",
            "Unknown": "light"
        }
        return color_map.get(grade, "light")
    
    def _get_html_template(self) -> str:
        """Get the HTML template string."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenShift AI Security Manifest - {{ metadata.release }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .grade-A { background-color: #d4edda; color: #155724; }
        .grade-B { background-color: #d1ecf1; color: #0c5460; }
        .grade-C { background-color: #fff3cd; color: #856404; }
        .grade-D { background-color: #f8d7da; color: #721c24; }
        .grade-F { background-color: #f5c6cb; color: #721c24; }
        .security-posture-good { color: #28a745; }
        .security-posture-concerning { color: #ffc107; }
        .security-posture-critical { color: #dc3545; }
        .severity-chart { height: 200px; }
        .container-card { transition: transform 0.2s; }
        .container-card:hover { transform: translateY(-2px); }
        .vulnerability-badge { font-size: 0.8em; }
        .grade-badge { font-size: 1.2em; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <header class="bg-primary text-white py-4 mb-4">
            <div class="container">
                <div class="row align-items-center">
                    <div class="col-md-6">
                        <h1 class="mb-0">
                            <i class="fas fa-shield-alt me-2"></i>
                            OpenShift AI Security Manifest
                        </h1>
                        <p class="mb-0 opacity-75">Release {{ metadata.release }}</p>
                    </div>
                    <div class="col-md-6 text-md-end">
                        <div class="text-info">
                            <i class="fas fa-calendar me-1"></i>
                            Generated: {{ metadata.generated_at | datetime }}
                        </div>
                        <div class="text-info">
                            <i class="fas fa-cube me-1"></i>
                            {{ metadata.total_containers }} Containers
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <div class="container">
            <!-- Executive Summary -->
            <section class="mb-5">
                <h2 class="mb-3">
                    <i class="fas fa-chart-line me-2"></i>
                    Executive Summary
                </h2>
                
                <div class="row">
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3 class="card-title text-primary">{{ summary.average_score }}%</h3>
                                <p class="card-text">Average Security Score</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3 class="card-title text-info">{{ summary.total_vulnerabilities }}</h3>
                                <p class="card-text">Total Vulnerabilities</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3 class="card-title security-posture-{{ summary.security_posture }}">
                                    {{ summary.security_posture | title }}
                                </h3>
                                <p class="card-text">Security Posture</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3 class="card-title text-success">{{ summary.average_vulnerabilities }}</h3>
                                <p class="card-text">Avg Vulns/Container</p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Grade Distribution -->
            <section class="mb-5">
                <h2 class="mb-3">
                    <i class="fas fa-graduation-cap me-2"></i>
                    Security Grade Distribution
                </h2>
                
                <div class="row">
                    {% for grade, count in summary.grade_distribution.items() %}
                    <div class="col-md-2">
                        <div class="card grade-{{ grade }} text-center">
                            <div class="card-body">
                                <h4 class="card-title">{{ grade }}</h4>
                                <p class="card-text">{{ count }} containers</p>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <!-- Vulnerability Summary -->
            <section class="mb-5">
                <h2 class="mb-3">
                    <i class="fas fa-bug me-2"></i>
                    Vulnerability Summary
                </h2>
                
                <div class="row">
                    {% for severity, count in severity_totals.items() %}
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-body text-center">
                                <span class="badge bg-{{ severity | severity_color }} badge-lg">
                                    {{ count }}
                                </span>
                                <h5 class="mt-2">{{ severity }}</h5>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <!-- Container Analysis -->
            <section class="mb-5">
                <h2 class="mb-3">
                    <i class="fas fa-cubes me-2"></i>
                    Container Analysis
                </h2>
                
                <div class="row">
                    {% for container in containers %}
                    <div class="col-md-6 mb-4">
                        <div class="card container-card h-100">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">
                                    <i class="fas fa-cube me-2"></i>
                                    {{ container.name }}
                                </h5>
                                <span class="badge grade-badge grade-{{ container.security_grade }}">
                                    {{ container.security_grade }}
                                </span>
                            </div>
                            <div class="card-body">
                                <div class="row mb-3">
                                    <div class="col-sm-6">
                                        <strong>Security Score:</strong><br>
                                        <span class="fs-4 text-primary">{{ container.security_score }}%</span>
                                    </div>
                                    <div class="col-sm-6">
                                        <strong>Total Vulnerabilities:</strong><br>
                                        <span class="fs-4 text-danger">{{ container.total_vulnerabilities }}</span>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <strong>Vulnerability Breakdown:</strong><br>
                                    {% for severity, count in container.vulnerabilities.items() %}
                                    {% if count > 0 %}
                                    <span class="badge bg-{{ severity | severity_color }} vulnerability-badge me-1">
                                        {{ severity }}: {{ count }}
                                    </span>
                                    {% endif %}
                                    {% endfor %}
                                </div>
                                
                                <div class="row text-muted small">
                                    <div class="col-sm-6">
                                        <i class="fas fa-box me-1"></i>
                                        Packages: {{ container.packages_scanned }}
                                    </div>
                                    <div class="col-sm-6">
                                        <i class="fas fa-clock me-1"></i>
                                        Scanned: {{ container.last_scanned | datetime }}
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer">
                                <small class="text-muted">
                                    <i class="fas fa-docker me-1"></i>
                                    {{ container.registry_url | truncate(60) }}
                                </small>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <!-- Footer -->
            <footer class="text-center text-muted py-4 border-top">
                <p class="mb-0">
                    Generated by OpenShift AI Security Manifest Tool v{{ metadata.tool_version }}
                </p>
                <p class="mb-0">
                    <i class="fas fa-info-circle me-1"></i>
                    This report provides a comprehensive security analysis of container images in the OpenShift AI release.
                </p>
            </footer>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Chart.js for potential future use -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
        // Add any interactive features here
        document.addEventListener('DOMContentLoaded', function() {
            // Tooltip initialization
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        });
    </script>
</body>
</html>
        """