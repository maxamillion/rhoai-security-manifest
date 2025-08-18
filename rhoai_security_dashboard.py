#!/usr/bin/env python3
"""
RHOAI Security Dashboard

A Streamlit web application that displays security data from the rhoai_security_pyxis.py script
in an interactive dashboard format, inspired by Red Hat Ecosystem Catalog design.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="RHOAI Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Red Hat inspired styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #EE0000 0%, #CC0000 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 2rem;
        text-align: center;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border-left: 4px solid #EE0000;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }
    
    .status-good { color: #3E8635; font-weight: bold; }
    .status-warning { color: #F0AB00; font-weight: bold; }
    .status-critical { color: #C9190B; font-weight: bold; }
    
    .cve-link {
        color: #0066CC;
        text-decoration: none;
    }
    
    .cve-link:hover {
        text-decoration: underline;
    }
    
    .sidebar .sidebar-content {
        background-color: #F5F5F5;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: #F5F5F5;
        border-radius: 4px 4px 0px 0px;
        padding: 10px 20px;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #EE0000;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_security_data(file_path):
    """Load security data from JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        st.error(f"Data file not found: {file_path}")
        return None
    except json.JSONDecodeError:
        st.error(f"Invalid JSON format in file: {file_path}")
        return None

def execute_security_script(release_version, output_format="json"):
    """Execute the rhoai_security_pyxis.py script to generate fresh data."""
    script_path = "./rhoai_security_pyxis.py"
    
    if not os.path.exists(script_path):
        st.error("rhoai_security_pyxis.py script not found in current directory")
        return None
    
    try:
        # Generate timestamp-based filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"rhoai_security_{release_version}_{timestamp}.json"
        
        # Execute script using uv run
        cmd = [
            "uv", "run", "python", script_path, 
            "--release", release_version,
            "--format", output_format,
            "--output", output_file,
            "--log-level", "WARNING"
        ]
        
        with st.spinner(f"Fetching security data for RHOAI {release_version}..."):
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            st.success(f"Security data updated successfully! Generated: {output_file}")
            return output_file
        else:
            st.error(f"Script execution failed: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        st.error("Script execution timed out (5 minutes)")
        return None
    except Exception as e:
        st.error(f"Error executing script: {str(e)}")
        return None

def process_security_data(data):
    """Process raw security data into dashboard-friendly formats."""
    if not data or 'images' not in data:
        return None, None, None
    
    images = data['images']
    metadata = data.get('metadata', {})
    unique_cves = data.get('unique_cves', [])
    
    # Create DataFrame for images
    image_records = []
    for img in images:
        # Extract image name
        image_name = get_image_display_name(img)
        
        # Extract freshness grade
        freshness_grade = img.get('freshness_grades', [{}])[0].get('grade', 'Unknown')
        
        # CVE count
        cve_count = len(img.get('cves', []))
        
        # Advisory URL
        advisory_url = get_advisory_url(img)
        
        image_records.append({
            'Image Name': image_name,
            'Image ID': img.get('_id', ''),
            'Freshness Grade': freshness_grade,
            'CVE Count': cve_count,
            'CVEs': img.get('cves', []),
            'Advisory URL': advisory_url,
            'Creation Date': img.get('creation_date', '')
        })
    
    df = pd.DataFrame(image_records)
    
    return df, metadata, unique_cves

def get_image_display_name(image):
    """Extract display name from image data."""
    try:
        if image.get("repositories") and len(image["repositories"]) > 0:
            registry = image["repositories"][0].get("registry", "")
            repository = image["repositories"][0].get("repository", "")
            
            if registry and repository:
                base_name = f"{registry}/{repository}"
                
                # Try to extract SHA256 digest
                image_id = image.get("image_id", "")
                if image_id and image_id.startswith("sha256:"):
                    sha256_hash = image_id.replace("sha256:", "")
                    if len(sha256_hash) >= 8:
                        return f"{base_name}:{sha256_hash[:8]}"
                
                return base_name
        
        # Fallback to display_data
        if image.get("display_data") and image["display_data"].get("name"):
            return image["display_data"]["name"]
        
        return image.get("_id", "unknown")
        
    except (KeyError, TypeError, IndexError):
        return "unknown"

def get_advisory_url(image):
    """Extract advisory URL from image data."""
    try:
        if (image.get("repositories") and 
            len(image["repositories"]) > 0 and 
            image["repositories"][0].get("_links", {}).get("image_advisory", {}).get("href")):
            
            href = image["repositories"][0]["_links"]["image_advisory"]["href"]
            advisory_id = href.split('/')[-1]
            return f"https://access.redhat.com/errata/{advisory_id}"
    except (KeyError, TypeError, IndexError):
        pass
    
    return ""

def create_summary_metrics(df, metadata, unique_cves):
    """Create summary metrics for the dashboard."""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Images",
            value=len(df) if df is not None else 0,
            help="Total number of container images analyzed"
        )
    
    with col2:
        st.metric(
            label="Unique CVEs",
            value=len(unique_cves),
            help="Total number of unique Common Vulnerabilities and Exposures"
        )
    
    with col3:
        if df is not None and len(df) > 0:
            avg_cves = df['CVE Count'].mean()
            st.metric(
                label="Avg CVEs per Image",
                value=f"{avg_cves:.1f}",
                help="Average number of CVEs per container image"
            )
        else:
            st.metric(label="Avg CVEs per Image", value="0")
    
    with col4:
        if df is not None and len(df) > 0:
            grade_a_count = len(df[df['Freshness Grade'] == 'A'])
            grade_a_pct = (grade_a_count / len(df)) * 100
            st.metric(
                label="Grade A Images",
                value=f"{grade_a_pct:.1f}%",
                help="Percentage of images with Grade A freshness rating"
            )
        else:
            st.metric(label="Grade A Images", value="0%")

def create_freshness_chart(df):
    """Create freshness grade distribution chart."""
    if df is None or len(df) == 0:
        st.info("No data available for freshness chart")
        return
    
    grade_counts = df['Freshness Grade'].value_counts()
    
    # Define colors for grades
    color_map = {
        'A': '#3E8635',  # Green
        'B': '#F0AB00',  # Yellow  
        'C': '#F0AB00',  # Yellow
        'D': '#C9190B',  # Red
        'F': '#C9190B'   # Red
    }
    
    colors = [color_map.get(grade, '#6A6E73') for grade in grade_counts.index]
    
    fig = px.bar(
        x=grade_counts.index, 
        y=grade_counts.values,
        color=grade_counts.index,
        color_discrete_map=color_map,
        title="Image Freshness Grade Distribution",
        labels={'x': 'Freshness Grade', 'y': 'Number of Images'}
    )
    
    fig.update_layout(
        showlegend=False,
        height=400,
        title_font_size=16
    )
    
    st.plotly_chart(fig, use_container_width=True)

def create_cve_distribution_chart(df):
    """Create CVE count distribution chart."""
    if df is None or len(df) == 0:
        st.info("No data available for CVE distribution chart")
        return
    
    # Create CVE count bins
    cve_counts = df['CVE Count']
    
    if cve_counts.max() == 0:
        st.info("No CVEs found in the analyzed images")
        return
    
    # Create histogram
    fig = px.histogram(
        df, 
        x='CVE Count',
        nbins=20,
        title="CVE Count Distribution Across Images",
        labels={'CVE Count': 'Number of CVEs', 'count': 'Number of Images'},
        color_discrete_sequence=['#EE0000']
    )
    
    fig.update_layout(
        height=400,
        title_font_size=16,
        bargap=0.1
    )
    
    st.plotly_chart(fig, use_container_width=True)

def format_freshness_grade(grade):
    """Format freshness grade with appropriate styling."""
    if grade == 'A':
        return f'<span class="status-good">{grade}</span>'
    elif grade in ['B', 'C']:
        return f'<span class="status-warning">{grade}</span>'
    else:
        return f'<span class="status-critical">{grade}</span>'

def main():
    """Main dashboard application."""
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ RHOAI Security Dashboard</h1>
        <p>Red Hat OpenShift AI Security Analysis & Vulnerability Overview</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for controls
    with st.sidebar:
        st.header("Dashboard Controls")
        
        # RHOAI Version selector
        release_version = st.selectbox(
            "Select RHOAI Version",
            options=["v2.21", "v2.22", "v2.23", "v2.24"],
            index=1,  # Default to v2.22
            help="Choose the RHOAI release version to analyze"
        )
        
        # Data source options
        st.subheader("Data Source")
        
        # Check for existing data files
        existing_files = list(Path(".").glob("rhoai_security_*.json"))
        existing_files = [f for f in existing_files if f.name != "rhoai_images.json"]
        
        data_source = st.radio(
            "Choose data source:",
            options=["Load existing file", "Generate fresh data"],
            help="Load from existing JSON file or fetch fresh data from Pyxis API"
        )
        
        data_file = None
        
        if data_source == "Load existing file":
            if existing_files:
                file_options = [f.name for f in existing_files]
                selected_file = st.selectbox("Select data file:", file_options)
                data_file = selected_file
            else:
                st.warning("No existing data files found. Please generate fresh data.")
                data_source = "Generate fresh data"
        
        if data_source == "Generate fresh data":
            if st.button("🔄 Fetch Security Data", type="primary"):
                data_file = execute_security_script(release_version)
        
        # Data refresh info
        if data_file and os.path.exists(data_file):
            file_time = datetime.fromtimestamp(os.path.getmtime(data_file))
            st.info(f"Data file: {data_file}")
            st.info(f"Last updated: {file_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Main content area
    if not data_file or not os.path.exists(data_file):
        st.warning("Please select a data file or generate fresh security data using the sidebar controls.")
        st.info("The dashboard will display RHOAI security information including CVE counts, freshness grades, and detailed vulnerability data.")
        return
    
    # Load and process data
    data = load_security_data(data_file)
    if data is None:
        return
    
    df, metadata, unique_cves = process_security_data(data)
    
    if df is None:
        st.error("Failed to process security data")
        return
    
    # Display metadata if available
    if metadata:
        st.subheader(f"Security Analysis for RHOAI {metadata.get('release', 'Unknown')}")
        st.caption(f"Generated: {metadata.get('generated_at', 'Unknown')}")
    
    # Summary metrics
    st.subheader("📊 Security Summary")
    create_summary_metrics(df, metadata, unique_cves)
    
    # Main dashboard tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Security Overview", "📋 Image Details", "🚨 CVE Analysis"])
    
    with tab1:
        st.subheader("Security Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            create_freshness_chart(df)
        
        with col2:
            create_cve_distribution_chart(df)
        
        # Top vulnerable images
        if len(df) > 0:
            st.subheader("Most Vulnerable Images")
            top_vulnerable = df.nlargest(5, 'CVE Count')[['Image Name', 'CVE Count', 'Freshness Grade']]
            
            # Format the dataframe for display
            display_df = top_vulnerable.copy()
            display_df['Freshness Grade'] = display_df['Freshness Grade'].apply(format_freshness_grade)
            
            st.markdown(display_df.to_html(escape=False, index=False), unsafe_allow_html=True)
    
    with tab2:
        st.subheader("Image Security Details")
        
        if len(df) > 0:
            # Search/filter options
            col1, col2 = st.columns([2, 1])
            
            with col1:
                search_term = st.text_input("🔍 Search images:", placeholder="Enter image name or ID...")
            
            with col2:
                grade_filter = st.multiselect(
                    "Filter by Grade:",
                    options=df['Freshness Grade'].unique(),
                    default=df['Freshness Grade'].unique()
                )
            
            # Apply filters
            filtered_df = df[df['Freshness Grade'].isin(grade_filter)]
            
            if search_term:
                filtered_df = filtered_df[
                    filtered_df['Image Name'].str.contains(search_term, case=False, na=False) |
                    filtered_df['Image ID'].str.contains(search_term, case=False, na=False)
                ]
            
            # Display filtered results
            st.write(f"Showing {len(filtered_df)} of {len(df)} images")
            
            # Create expandable rows for detailed view
            for idx, row in filtered_df.iterrows():
                with st.expander(f"📦 {row['Image Name']} (Grade: {row['Freshness Grade']}, CVEs: {row['CVE Count']})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Image ID:** {row['Image ID']}")
                        st.write(f"**Creation Date:** {row['Creation Date']}")
                        st.write(f"**Freshness Grade:** {row['Freshness Grade']}")
                    
                    with col2:
                        st.write(f"**CVE Count:** {row['CVE Count']}")
                        if row['Advisory URL']:
                            st.markdown(f"**Advisory:** [{row['Advisory URL']}]({row['Advisory URL']})")
                    
                    # CVE list
                    if row['CVEs']:
                        st.write("**CVEs:**")
                        for cve_url in row['CVEs']:
                            cve_id = cve_url.split('/')[-1]
                            st.markdown(f"- [{cve_id}]({cve_url})")
                    else:
                        st.success("✅ No CVEs found for this image")
        else:
            st.info("No image data available")
    
    with tab3:
        st.subheader("CVE Analysis")
        
        if unique_cves:
            st.write(f"**Total Unique CVEs:** {len(unique_cves)}")
            
            # CVE frequency analysis
            cve_frequencies = {}
            for _, row in df.iterrows():
                for cve_url in row['CVEs']:
                    cve_id = cve_url.split('/')[-1]
                    cve_frequencies[cve_id] = cve_frequencies.get(cve_id, 0) + 1
            
            if cve_frequencies:
                st.subheader("Most Common CVEs")
                freq_df = pd.DataFrame(list(cve_frequencies.items()), columns=['CVE ID', 'Frequency'])
                freq_df = freq_df.sort_values('Frequency', ascending=False).head(10)
                
                fig = px.bar(
                    freq_df, 
                    x='CVE ID', 
                    y='Frequency',
                    title="Top 10 Most Frequent CVEs",
                    color_discrete_sequence=['#EE0000']
                )
                fig.update_xaxes(tickangle=45)
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            
            # Complete CVE list
            st.subheader("Complete CVE List")
            
            # Create CVE DataFrame with links
            cve_data = []
            for cve_url in sorted(unique_cves):
                cve_id = cve_url.split('/')[-1]
                frequency = cve_frequencies.get(cve_id, 0)
                cve_data.append({
                    'CVE ID': cve_id,
                    'Frequency': frequency,
                    'Red Hat Advisory': cve_url
                })
            
            cve_df = pd.DataFrame(cve_data)
            
            # Add search for CVEs
            cve_search = st.text_input("🔍 Search CVEs:", placeholder="Enter CVE ID...")
            
            if cve_search:
                cve_df = cve_df[cve_df['CVE ID'].str.contains(cve_search, case=False, na=False)]
            
            # Display CVE table with clickable links
            st.write(f"Showing {len(cve_df)} CVEs")
            
            # Convert to HTML for clickable links
            def make_clickable(url):
                return f'<a href="{url}" target="_blank" class="cve-link">🔗 View Advisory</a>'
            
            cve_display = cve_df.copy()
            cve_display['Red Hat Advisory'] = cve_display['Red Hat Advisory'].apply(make_clickable)
            
            st.markdown(cve_display.to_html(escape=False, index=False), unsafe_allow_html=True)
            
        else:
            st.success("✅ No CVEs found in the analyzed images!")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #6A6E73; font-size: 0.9em;">
        <p>Data sourced from Red Hat Pyxis API • Generated with rhoai_security_pyxis.py</p>
        <p>For more information, visit <a href="https://catalog.redhat.com" target="_blank">Red Hat Ecosystem Catalog</a></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()