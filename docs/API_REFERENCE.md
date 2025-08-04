# RHOAI Security Manifest Tool - API Reference

## Table of Contents
- [Overview](#overview)
- [Core Classes](#core-classes)
- [CLI Commands](#cli-commands)
- [Analysis Engine](#analysis-engine)
- [Database Models](#database-models)
- [API Clients](#api-clients)
- [Report Generators](#report-generators)
- [Configuration](#configuration)
- [Examples](#examples)

## Overview

This document provides comprehensive API reference for developers who want to extend, integrate, or contribute to the RHOAI Security Manifest Tool.

## Core Classes

### SecurityAnalysisOrchestrator

The main orchestrator that coordinates the complete security analysis workflow.

```python
from rhoai_security_manifest.analysis.orchestrator import SecurityAnalysisOrchestrator

class SecurityAnalysisOrchestrator:
    def __init__(
        self,
        catalog_client: ContainerCatalogClient,
        security_client: SecurityDataClient,
        grader: SecurityGrader,
        database_session_factory=SessionLocal,
    )
```

#### Methods

##### `analyze_release()`
Performs complete security analysis for a release.

```python
async def analyze_release(
    self,
    release_version: str,
    force_refresh: bool = False,
    offline_mode: bool = False,
    container_filter: Optional[List[str]] = None,
    include_packages: bool = False,
) -> AnalysisResult
```

**Parameters:**
- `release_version` (str): Release version to analyze (e.g., "2.8.0")
- `force_refresh` (bool): Ignore cache and refresh all data
- `offline_mode` (bool): Use cached data only
- `container_filter` (Optional[List[str]]): Container names to analyze
- `include_packages` (bool): Include package-level vulnerability details

**Returns:**
- `AnalysisResult`: Complete analysis results

**Example:**
```python
# Create orchestrator
orchestrator = await create_orchestrator(config)

# Run analysis
result = await orchestrator.analyze_release(
    release_version="2.8.0",
    include_packages=True
)

# Access results
print(f"Analyzed {len(result.containers)} containers")
print(f"Security posture: {result.summary['security_posture']}")
```

### SecurityGrader

Security grading engine for container images.

```python
from rhoai_security_manifest.analysis.grading import SecurityGrader, GradingCriteria

class SecurityGrader:
    def __init__(self, criteria: Optional[GradingCriteria] = None)
```

#### Methods

##### `grade_container()`
Grades a container's security posture.

```python
def grade_container(
    self, 
    security_info: ContainerSecurityInfo, 
    redhat_grade: Optional[str] = None
) -> Tuple[SecurityGrade, int, Dict[str, any]]
```

**Parameters:**
- `security_info` (ContainerSecurityInfo): Container security information
- `redhat_grade` (Optional[str]): Red Hat provided grade

**Returns:**
- Tuple of (grade, score, breakdown_details)

**Example:**
```python
grader = SecurityGrader()
grade, score, breakdown = grader.grade_container(security_info)

print(f"Grade: {grade.value}, Score: {score}")
print(f"Breakdown: {breakdown}")
```

##### `grade_multiple_containers()`
Grades multiple containers efficiently.

```python
def grade_multiple_containers(
    self,
    containers_info: List[ContainerSecurityInfo],
    redhat_grades: Optional[Dict[str, str]] = None,
) -> List[Tuple[str, SecurityGrade, int, Dict[str, any]]]
```

### GradingCriteria

Configuration for security grading algorithm.

```python
class GradingCriteria:
    def __init__(self):
        self.severity_weights = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 1,
        }
        self.grade_thresholds = {
            SecurityGrade.A: (90, 100),
            SecurityGrade.B: (80, 89),
            SecurityGrade.C: (70, 79),
            SecurityGrade.D: (60, 69),
            SecurityGrade.F: (0, 59),
        }
```

#### Methods

##### `update_weights()`
Updates grading weights dynamically.

```python
def update_weights(self, **kwargs) -> None
```

**Example:**
```python
criteria = GradingCriteria()
criteria.update_weights(
    severity_weights={Severity.CRITICAL: 25},
    unpatched_critical_penalty=15
)
```

## CLI Commands

### Command Structure

All CLI commands follow this pattern:

```python
@click.command()
@click.option("--option", help="Description")
@click.pass_context
def command_name(ctx: click.Context, option: str):
    """Command description."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    # Implementation
```

### Generate Command

```python
from rhoai_security_manifest.cli.commands.generate import generate

@click.command()
@click.option("--release", required=True)
@click.option("--format", type=click.Choice(["json", "csv", "html", "markdown"]))
@click.option("--output", type=click.Path(path_type=Path))
@click.option("--packages", is_flag=True)
@click.option("--offline", is_flag=True)
@click.option("--force-refresh", is_flag=True)
@click.option("--containers", multiple=True)
def generate(ctx, release, format, output, packages, offline, force_refresh, containers):
    """Generate security manifest for an OpenShift AI release."""
```

### Adding Custom Commands

```python
# custom_command.py
import click
from rich.console import Console

@click.command()
@click.option("--param", help="Custom parameter")
@click.pass_context
def my_custom_command(ctx: click.Context, param: str):
    """My custom command description."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    
    # Your implementation here
    logger.info(f"Executing custom command with param: {param}")

# Register in main.py
from .commands.my_custom_command import my_custom_command
cli.add_command(my_custom_command)
```

## Analysis Engine

### AnalysisResult

Container for complete analysis results.

```python
class AnalysisResult:
    def __init__(
        self,
        release_version: str,
        containers: List[Dict[str, Any]],
        summary: Dict[str, Any],
        metadata: Dict[str, Any],
    ):
        self.release_version = release_version
        self.containers = containers
        self.summary = summary
        self.metadata = metadata
        self.generated_at = datetime.now()
```

**Attributes:**
- `release_version` (str): Release version analyzed
- `containers` (List[Dict]): Container analysis results
- `summary` (Dict): Aggregate summary statistics
- `metadata` (Dict): Analysis metadata
- `generated_at` (datetime): Timestamp of analysis completion

### Creating Custom Orchestrators

```python
async def create_custom_orchestrator(config) -> SecurityAnalysisOrchestrator:
    """Create orchestrator with custom components."""
    
    # Custom grading criteria
    custom_criteria = GradingCriteria()
    custom_criteria.update_weights(severity_weights={
        Severity.CRITICAL: 30,  # More severe penalty
        Severity.HIGH: 15,
    })
    
    # Create components
    catalog_client = await create_catalog_client(config)
    security_client = await create_security_client(config)
    grader = SecurityGrader(custom_criteria)
    
    return SecurityAnalysisOrchestrator(
        catalog_client=catalog_client,
        security_client=security_client,
        grader=grader
    )
```

## Database Models

### Base Model Structure

All models inherit from SQLAlchemy's DeclarativeBase:

```python
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    """Base class for all database models."""
    pass
```

### Release Model

```python
class Release(Base):
    __tablename__ = "releases"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(TEXT, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, default=func.now())
    container_count: Mapped[int] = mapped_column(Integer, default=0)
    last_updated: Mapped[datetime] = mapped_column(TIMESTAMP, default=func.now())
    
    # Relationships
    containers: Mapped[List["Container"]] = relationship(
        "Container", back_populates="release", cascade="all, delete-orphan"
    )
```

### Container Model

```python
class Container(Base):
    __tablename__ = "containers"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    release_id: Mapped[int] = mapped_column(Integer, ForeignKey("releases.id"))
    name: Mapped[str] = mapped_column(TEXT, nullable=False)
    registry_url: Mapped[str] = mapped_column(TEXT, nullable=False)
    digest: Mapped[str] = mapped_column(TEXT, nullable=False)
    security_grade: Mapped[Optional[str]] = mapped_column(TEXT)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, default=func.now())
    last_scanned: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP)
    
    # Relationships
    release: Mapped["Release"] = relationship("Release", back_populates="containers")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="container", cascade="all, delete-orphan"
    )
```

### Repository Pattern

Access data through repository classes:

```python
from rhoai_security_manifest.database.repository import ReleaseRepository, ContainerRepository

# Usage
with SessionLocal() as session:
    release_repo = ReleaseRepository(session)
    container_repo = ContainerRepository(session)
    
    # Get release
    release = release_repo.get_by_version("2.8.0")
    
    # Get containers for release
    containers = container_repo.get_by_release(release.id)
```

## API Clients

### Container Catalog Client

Interfaces with Red Hat Container Catalog API.

```python
from rhoai_security_manifest.api.container_catalog import ContainerCatalogClient

class ContainerCatalogClient:
    def __init__(self, base_url: str = "https://catalog.redhat.com/api/containers/v1/"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
```

#### Methods

##### `discover_rhoai_containers()`
Discovers containers for RHOAI release.

```python
async def discover_rhoai_containers(
    self, 
    release_version: str, 
    container_filter: Optional[List[str]] = None
) -> List[ContainerImage]
```

**Example:**
```python
client = ContainerCatalogClient()
containers = await client.discover_rhoai_containers("2.8.0")
print(f"Found {len(containers)} containers")
```

### Security Data Client

Interfaces with Red Hat Security Data API.

```python
from rhoai_security_manifest.api.security_data import SecurityDataClient

class SecurityDataClient:
    def __init__(self, base_url: str = "https://access.redhat.com/labs/securitydataapi/"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
```

#### Methods

##### `bulk_analyze_containers()`
Analyzes security for multiple containers.

```python
async def bulk_analyze_containers(
    self, 
    container_data: List[Dict], 
    include_packages: bool = False
) -> List[ContainerSecurityInfo]
```

### Creating Custom API Clients

```python
class CustomSecurityClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {api_key}"}
        )
    
    async def get_vulnerabilities(self, container_digest: str) -> List[Dict]:
        """Get vulnerabilities from custom API."""
        response = await self.client.get(
            f"/api/v1/vulnerabilities/{container_digest}"
        )
        return response.json()
```

## Report Generators

### HTML Report Generator

```python
from rhoai_security_manifest.reports.generators.html import HTMLReportGenerator

class HTMLReportGenerator:
    def generate_report(self, report_data: dict, output_path: Path) -> None:
        """Generate HTML report with charts and interactive elements."""
```

### Creating Custom Report Generators

```python
class PDFReportGenerator:
    def __init__(self):
        self.template_engine = Jinja2Environment()
    
    def generate_report(self, report_data: dict, output_path: Path) -> None:
        """Generate PDF report."""
        # Render template
        template = self.template_engine.get_template("pdf_report.html")
        html_content = template.render(data=report_data)
        
        # Convert to PDF (using library like weasyprint)
        import weasyprint
        weasyprint.HTML(string=html_content).write_pdf(output_path)

# Register in generate.py
def _write_pdf_report(report_data: dict, output_path: Path) -> None:
    generator = PDFReportGenerator()
    generator.generate_report(report_data, output_path)
```

## Configuration

### Configuration Classes

```python
from rhoai_security_manifest.utils.config import Config, DatabaseConfig, APIConfig

@dataclass
class Config:
    database: DatabaseConfig
    api: APIConfig
    cache: CacheConfig
    reports: ReportsConfig
    logging: LoggingConfig
    debug: bool = False
    quiet: bool = False
    color_output: bool = True
```

### Loading Configuration

```python
from rhoai_security_manifest.utils.config import get_config, reset_config

# Load configuration
config = get_config("/path/to/config.yaml")

# Reset configuration (useful for testing)
reset_config()
```

### Custom Configuration

```python
def create_custom_config() -> Config:
    """Create configuration with custom settings."""
    return Config(
        database=DatabaseConfig(
            url="postgresql://user:pass@localhost/rhoai",
            retention_days=365
        ),
        api=APIConfig(
            timeout=60,
            max_retries=5,
            max_concurrent_requests=20
        ),
        # ... other configs
    )
```

## Examples

### Basic Integration Example

```python
import asyncio
from rhoai_security_manifest.analysis.orchestrator import create_orchestrator
from rhoai_security_manifest.utils.config import get_config

async def analyze_release(release_version: str):
    """Analyze a release and return results."""
    # Load configuration
    config = get_config()
    
    # Create orchestrator
    orchestrator = await create_orchestrator(config)
    
    try:
        # Run analysis
        result = await orchestrator.analyze_release(
            release_version=release_version,
            include_packages=True
        )
        
        # Process results
        print(f"Release: {result.release_version}")
        print(f"Containers: {len(result.containers)}")
        print(f"Average Score: {result.summary['average_score']}")
        
        return result
        
    finally:
        # Cleanup
        await orchestrator.catalog_client.close()
        await orchestrator.security_client.close()

# Usage
if __name__ == "__main__":
    result = asyncio.run(analyze_release("2.8.0"))
```

### Custom Grading Example

```python
from rhoai_security_manifest.analysis.grading import SecurityGrader, GradingCriteria

def create_strict_grader() -> SecurityGrader:
    """Create grader with stricter criteria."""
    criteria = GradingCriteria()
    
    # Stricter penalties
    criteria.update_weights(
        severity_weights={
            Severity.CRITICAL: 50,  # Very harsh
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 2,
        },
        unpatched_critical_penalty=20,
        grade_thresholds={
            SecurityGrade.A: (95, 100),  # Harder to achieve A
            SecurityGrade.B: (85, 94),
            SecurityGrade.C: (75, 84),
            SecurityGrade.D: (65, 74),
            SecurityGrade.F: (0, 64),
        }
    )
    
    return SecurityGrader(criteria)
```

### Database Integration Example

```python
from rhoai_security_manifest.database.models import SessionLocal
from rhoai_security_manifest.database.repository import ReleaseRepository

def get_release_history() -> List[Dict]:
    """Get historical release data."""
    with SessionLocal() as session:
        repo = ReleaseRepository(session)
        releases = repo.get_all()
        
        return [
            {
                "version": release.version,
                "containers": release.container_count,
                "created_at": release.created_at.isoformat(),
            }
            for release in releases
        ]
```

### CLI Extension Example

```python
import click
from rhoai_security_manifest.cli.main import cli

@cli.command()
@click.option("--release", required=True)
@click.option("--threshold", type=int, default=80)
@click.pass_context
def security_gate(ctx: click.Context, release: str, threshold: int):
    """Security gate that fails if average score below threshold."""
    # Run analysis
    result = asyncio.run(analyze_release(release))
    
    avg_score = result.summary["average_score"]
    
    if avg_score < threshold:
        click.echo(f"Security gate FAILED: {avg_score} < {threshold}", err=True)
        ctx.exit(1)
    else:
        click.echo(f"Security gate PASSED: {avg_score} >= {threshold}")
        ctx.exit(0)
```

---

This API reference provides the foundation for extending and integrating with the RHOAI Security Manifest Tool. For additional examples and advanced usage patterns, refer to the source code and test files.