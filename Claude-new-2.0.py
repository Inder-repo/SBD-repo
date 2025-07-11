import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import datetime
from typing import Dict, List, Optional
import uuid

# Configure page
st.set_page_config(
    page_title="ThreatForge - Enterprise STRIDE Threat Modeling",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #3b82f6;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 1rem 0;
    }
    
    .threat-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #ef4444;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 1rem 0;
    }
    
    .element-card {
        background: #f8fafc;
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
        margin: 0.5rem 0;
    }
    
    .stride-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.875rem;
        font-weight: 600;
        margin: 0.25rem;
    }
    
    .stride-s { background: #fee2e2; color: #991b1b; }
    .stride-t { background: #fed7aa; color: #9a3412; }
    .stride-r { background: #fef3c7; color: #92400e; }
    .stride-i { background: #dbeafe; color: #1e40af; }
    .stride-d { background: #e9d5ff; color: #7c3aed; }
    .stride-e { background: #fce7f3; color: #be185d; }
    
    .stSelectbox > div > div > div {
        background-color: #f8fafc;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'elements' not in st.session_state:
    st.session_state.elements = []
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = None
if 'selected_element' not in st.session_state:
    st.session_state.selected_element = None

# Element types configuration
ELEMENT_TYPES = {
    'process': {'name': 'Process', 'icon': '⚙️', 'color': '#3b82f6'},
    'datastore': {'name': 'Data Store', 'icon': '🗄️', 'color': '#10b981'},
    'external': {'name': 'External Entity', 'icon': '👤', 'color': '#8b5cf6'},
    'dataflow': {'name': 'Data Flow', 'icon': '🔄', 'color': '#f59e0b'},
    'trustboundary': {'name': 'Trust Boundary', 'icon': '🛡️', 'color': '#ef4444'}
}

# STRIDE categories
STRIDE_CATEGORIES = {
    'S': {'name': 'Spoofing', 'color': '#ef4444', 'icon': '🎭'},
    'T': {'name': 'Tampering', 'color': '#f59e0b', 'icon': '🔧'},
    'R': {'name': 'Repudiation', 'color': '#eab308', 'icon': '🚫'},
    'I': {'name': 'Information Disclosure', 'color': '#3b82f6', 'icon': '👁️'},
    'D': {'name': 'Denial of Service', 'color': '#8b5cf6', 'icon': '⛔'},
    'E': {'name': 'Elevation of Privilege', 'color': '#ec4899', 'icon': '⬆️'}
}

class ThreatModelGenerator:
    @staticmethod
    def generate_threats(elements: List[Dict]) -> List[Dict]:
        threats = []
        threat_id = 1
        
        for element in elements:
            element_threats = ThreatModelGenerator._get_element_threats(element)
            for threat in element_threats:
                threat['id'] = f"T{threat_id:03d}"
                threat['element_id'] = element['id']
                threat['element_name'] = element['name']
                threats.append(threat)
                threat_id += 1
        
        return threats
    
    @staticmethod
    def _get_element_threats(element: Dict) -> List[Dict]:
        element_type = element['type']
        base_threats = []
        
        if element_type == 'process':
            base_threats = [
                {
                    'category': 'S',
                    'threat': 'Process Identity Spoofing',
                    'description': 'An attacker could impersonate this process to gain unauthorized access to system resources',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Implement strong process authentication, code signing, and runtime integrity checks'
                },
                {
                    'category': 'T',
                    'threat': 'Process Memory/Code Tampering',
                    'description': 'Malicious modification of process execution flow or data in memory',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Use memory protection, control flow integrity, and secure deployment practices'
                },
                {
                    'category': 'D',
                    'threat': 'Process Resource Exhaustion',
                    'description': 'Denial of service through resource exhaustion or process termination',
                    'impact': 'Medium',
                    'likelihood': 'High',
                    'mitigation': 'Implement resource limits, rate limiting, and monitoring'
                },
                {
                    'category': 'E',
                    'threat': 'Privilege Escalation',
                    'description': 'Process could be exploited to gain higher privileges than intended',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Run with least privilege, implement proper access controls'
                }
            ]
        
        elif element_type == 'datastore':
            base_threats = [
                {
                    'category': 'I',
                    'threat': 'Unauthorized Data Access',
                    'description': 'Sensitive data could be accessed by unauthorized users or processes',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Implement encryption at rest, strong access controls, and audit logging'
                },
                {
                    'category': 'T',
                    'threat': 'Data Integrity Compromise',
                    'description': 'Data could be modified without authorization, affecting system integrity',
                    'impact': 'High',
                    'likelihood': 'Low',
                    'mitigation': 'Database integrity constraints, checksums, and transaction logging'
                },
                {
                    'category': 'D',
                    'threat': 'Data Availability Loss',
                    'description': 'Data store could become unavailable due to attacks or failures',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Implement backup strategies, redundancy, and disaster recovery'
                },
                {
                    'category': 'R',
                    'threat': 'Data Access Repudiation',
                    'description': 'Users could deny accessing or modifying data',
                    'impact': 'Medium',
                    'likelihood': 'Low',
                    'mitigation': 'Comprehensive audit trails and non-repudiation mechanisms'
                }
            ]
        
        elif element_type == 'external':
            base_threats = [
                {
                    'category': 'S',
                    'threat': 'Identity Spoofing',
                    'description': 'External entity identity could be falsified or impersonated',
                    'impact': 'High',
                    'likelihood': 'High',
                    'mitigation': 'Multi-factor authentication, digital certificates, and identity verification'
                },
                {
                    'category': 'R',
                    'threat': 'Action Repudiation',
                    'description': 'External entity could deny performing actions or transactions',
                    'impact': 'Medium',
                    'likelihood': 'Medium',
                    'mitigation': 'Digital signatures, audit logging, and non-repudiation protocols'
                },
                {
                    'category': 'T',
                    'threat': 'Input Tampering',
                    'description': 'Malicious input could be provided to compromise system integrity',
                    'impact': 'High',
                    'likelihood': 'High',
                    'mitigation': 'Input validation, sanitization, and security controls'
                }
            ]
        
        elif element_type == 'dataflow':
            base_threats = [
                {
                    'category': 'I',
                    'threat': 'Data Interception',
                    'description': 'Data in transit could be intercepted and read by unauthorized parties',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Implement encryption in transit (TLS/SSL) and secure protocols'
                },
                {
                    'category': 'T',
                    'threat': 'Data Modification in Transit',
                    'description': 'Data could be altered during transmission without detection',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Message authentication codes, digital signatures, and integrity checks'
                },
                {
                    'category': 'D',
                    'threat': 'Communication Disruption',
                    'description': 'Data flow could be interrupted or blocked by attackers',
                    'impact': 'Medium',
                    'likelihood': 'Medium',
                    'mitigation': 'Redundant communication paths and DDoS protection'
                }
            ]
        
        elif element_type == 'trustboundary':
            base_threats = [
                {
                    'category': 'S',
                    'threat': 'Trust Boundary Bypass',
                    'description': 'Attackers could bypass security controls at trust boundaries',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Strong boundary enforcement, access controls, and monitoring'
                },
                {
                    'category': 'E',
                    'threat': 'Cross-Boundary Privilege Escalation',
                    'description': 'Privileges could be escalated across trust boundaries',
                    'impact': 'High',
                    'likelihood': 'Medium',
                    'mitigation': 'Principle of least privilege and boundary security controls'
                }
            ]
        
        return base_threats

def render_header():
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ ThreatForge</h1>
        <h3>Enterprise STRIDE Threat Modeling Platform</h3>
        <p>Professional threat modeling and security analysis for enterprise applications</p>
    </div>
    """, unsafe_allow_html=True)

def render_sidebar():
    st.sidebar.title("🔧 Design Elements")
    
    # Element creation
    st.sidebar.subheader("Add New Element")
    
    element_type = st.sidebar.selectbox(
        "Select Element Type",
        options=list(ELEMENT_TYPES.keys()),
        format_func=lambda x: f"{ELEMENT_TYPES[x]['icon']} {ELEMENT_TYPES[x]['name']}"
    )
    
    element_name = st.sidebar.text_input("Element Name", f"New {ELEMENT_TYPES[element_type]['name']}")
    
    if st.sidebar.button("➕ Add Element", use_container_width=True):
        new_element = {
            'id': str(uuid.uuid4()),
            'type': element_type,
            'name': element_name,
            'description': '',
            'properties': {
                'authentication': '',
                'encryption': '',
                'protocols': [],
                'data_types': []
            }
        }
        st.session_state.elements.append(new_element)
        st.rerun()
    
    # Current elements
    st.sidebar.subheader("Current Elements")
    
    if st.session_state.elements:
        for i, element in enumerate(st.session_state.elements):
            with st.sidebar.expander(f"{ELEMENT_TYPES[element['type']]['icon']} {element['name']}", expanded=False):
                # Element properties
                new_name = st.text_input("Name", element['name'], key=f"name_{element['id']}")
                new_desc = st.text_area("Description", element['description'], key=f"desc_{element['id']}")
                new_auth = st.text_input("Authentication", element['properties']['authentication'], key=f"auth_{element['id']}")
                new_enc = st.text_input("Encryption", element['properties']['encryption'], key=f"enc_{element['id']}")
                
                # Update element
                if st.button("Update", key=f"update_{element['id']}"):
                    st.session_state.elements[i]['name'] = new_name
                    st.session_state.elements[i]['description'] = new_desc
                    st.session_state.elements[i]['properties']['authentication'] = new_auth
                    st.session_state.elements[i]['properties']['encryption'] = new_enc
                    st.rerun()
                
                # Delete element
                if st.button("🗑️ Delete", key=f"delete_{element['id']}", type="secondary"):
                    st.session_state.elements.pop(i)
                    st.rerun()
    else:
        st.sidebar.info("No elements added yet. Add elements to start building your threat model.")

def render_threat_analysis():
    st.header("🔍 Threat Analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.button("🚀 Generate STRIDE Threat Model", type="primary", use_container_width=True):
            if st.session_state.elements:
                with st.spinner("Analyzing threats using STRIDE methodology..."):
                    threats = ThreatModelGenerator.generate_threats(st.session_state.elements)
                    
                    risk_summary = {
                        'total_threats': len(threats),
                        'high_risk': len([t for t in threats if t['impact'] == 'High']),
                        'medium_risk': len([t for t in threats if t['impact'] == 'Medium']),
                        'low_risk': len([t for t in threats if t['impact'] == 'Low']),
                        'elements': len(st.session_state.elements)
                    }
                    
                    st.session_state.threat_model = {
                        'threats': threats,
                        'risk_summary': risk_summary,
                        'generated_at': datetime.datetime.now().isoformat()
                    }
                    
                st.success("✅ Threat model generated successfully!")
                st.rerun()
            else:
                st.error("❌ Please add at least one element to generate a threat model.")
    
    with col2:
        if st.session_state.threat_model:
            if st.button("📊 View Detailed Report", use_container_width=True):
                st.session_state.show_report = True
                st.rerun()

def render_dashboard():
    if not st.session_state.threat_model:
        st.info("🚀 Add elements and generate a threat model to see the dashboard.")
        return
    
    st.header("📊 Threat Model Dashboard")
    
    risk_summary = st.session_state.threat_model['risk_summary']
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Elements", risk_summary['elements'], help="Number of system elements modeled")
    
    with col2:
        st.metric("Total Threats", risk_summary['total_threats'], help="Total identified threats")
    
    with col3:
        st.metric("High Risk", risk_summary['high_risk'], help="High impact threats requiring immediate attention")
    
    with col4:
        st.metric("Medium Risk", risk_summary['medium_risk'], help="Medium impact threats for planning")
    
    # Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk distribution pie chart
        risk_data = {
            'Risk Level': ['High', 'Medium', 'Low'],
            'Count': [risk_summary['high_risk'], risk_summary['medium_risk'], risk_summary['low_risk']],
            'Color': ['#ef4444', '#f59e0b', '#10b981']
        }
        
        fig_pie = px.pie(
            values=risk_data['Count'],
            names=risk_data['Risk Level'],
            title="Risk Distribution",
            color_discrete_sequence=risk_data['Color']
        )
        fig_pie.update_layout(showlegend=True)
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # STRIDE category distribution
        threats = st.session_state.threat_model['threats']
        stride_counts = {}
        for threat in threats:
            category = threat['category']
            stride_counts[category] = stride_counts.get(category, 0) + 1
        
        stride_data = pd.DataFrame([
            {'Category': f"{cat} - {STRIDE_CATEGORIES[cat]['name']}", 'Count': count}
            for cat, count in stride_counts.items()
        ])
        
        fig_bar = px.bar(
            stride_data,
            x='Category',
            y='Count',
            title="STRIDE Category Distribution",
            color='Count',
            color_continuous_scale='viridis'
        )
        fig_bar.update_layout(showlegend=False)
        st.plotly_chart(fig_bar, use_container_width=True)

def render_threat_details():
    if not st.session_state.threat_model:
        return
    
    st.header("🎯 Detailed Threat Analysis")
    
    threats = st.session_state.threat_model['threats']
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        impact_filter = st.selectbox("Filter by Impact", ['All', 'High', 'Medium', 'Low'])
    
    with col2:
        stride_filter = st.selectbox(
            "Filter by STRIDE Category",
            ['All'] + [f"{cat} - {STRIDE_CATEGORIES[cat]['name']}" for cat in STRIDE_CATEGORIES.keys()]
        )
    
    with col3:
        element_filter = st.selectbox(
            "Filter by Element",
            ['All'] + [elem['name'] for elem in st.session_state.elements]
        )
    
    # Apply filters
    filtered_threats = threats.copy()
    
    if impact_filter != 'All':
        filtered_threats = [t for t in filtered_threats if t['impact'] == impact_filter]
    
    if stride_filter != 'All':
        stride_cat = stride_filter.split(' - ')[0]
        filtered_threats = [t for t in filtered_threats if t['category'] == stride_cat]
    
    if element_filter != 'All':
        filtered_threats = [t for t in filtered_threats if t['element_name'] == element_filter]
    
    # Display threats
    st.subheader(f"Found {len(filtered_threats)} threats")
    
    for threat in filtered_threats:
        with st.expander(f"🚨 {threat['id']}: {threat['threat']}", expanded=False):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**Element:** {threat['element_name']}")
                st.write(f"**Description:** {threat['description']}")
                st.write(f"**Mitigation:** {threat['mitigation']}")
            
            with col2:
                stride_cat = STRIDE_CATEGORIES[threat['category']]
                st.markdown(f"""
                <div class="stride-badge stride-{threat['category'].lower()}">
                    {stride_cat['icon']} {stride_cat['name']}
                </div>
                """, unsafe_allow_html=True)
                
                impact_color = {
                    'High': '#ef4444',
                    'Medium': '#f59e0b',
                    'Low': '#10b981'
                }.get(threat['impact'], '#6b7280')
                
                st.markdown(f"""
                <div style="background: {impact_color}; color: white; padding: 0.5rem; border-radius: 5px; text-align: center; margin-top: 1rem;">
                    <strong>{threat['impact']} Impact</strong>
                </div>
                """, unsafe_allow_html=True)

def render_export_section():
    if not st.session_state.threat_model:
        return
    
    st.header("📤 Export & Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Export Options")
        
        # JSON export
        if st.button("📄 Export as JSON", use_container_width=True):
            export_data = {
                'elements': st.session_state.elements,
                'threat_model': st.session_state.threat_model,
                'metadata': {
                    'created': datetime.datetime.now().isoformat(),
                    'tool': 'ThreatForge Streamlit',
                    'version': '1.0'
                }
            }
            
            st.download_button(
                label="💾 Download JSON",
                data=json.dumps(export_data, indent=2),
                file_name=f"threat_model_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        # CSV export
        if st.button("📊 Export Threats as CSV", use_container_width=True):
            threats_df = pd.DataFrame(st.session_state.threat_model['threats'])
            csv = threats_df.to_csv(index=False)
            
            st.download_button(
                label="💾 Download CSV",
                data=csv,
                file_name=f"threats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col2:
        st.subheader("Summary Report")
        
        if st.session_state.threat_model:
            risk_summary = st.session_state.threat_model['risk_summary']
            
            report = f"""
            # Threat Model Summary Report
            
            **Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            ## System Overview
            - **Total Elements:** {risk_summary['elements']}
            - **Total Threats:** {risk_summary['total_threats']}
            
            ## Risk Summary
            - **High Risk Threats:** {risk_summary['high_risk']}
            - **Medium Risk Threats:** {risk_summary['medium_risk']}
            - **Low Risk Threats:** {risk_summary['low_risk']}
            
            ## Recommendations
            1. Address all high-risk threats immediately
            2. Plan mitigation for medium-risk threats
            3. Monitor and review low-risk threats regularly
            4. Implement defense-in-depth strategies
            5. Regular security assessments and updates
            """
            
            st.markdown(report)
            
            st.download_button(
                label="📋 Download Summary Report",
                data=report,
                file_name=f"threat_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )

def main():
    # Render header
    render_header()
    
    # Render sidebar
    render_sidebar()
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🏗️ Design", "🔍 Analysis", "📊 Dashboard", "📤 Export"])
    
    with tab1:
        st.header("🏗️ System Design")
        
        if st.session_state.elements:
            st.subheader("Current System Elements")
            
            for element in st.session_state.elements:
                with st.expander(f"{ELEMENT_TYPES[element['type']]['icon']} {element['name']}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Type:** {ELEMENT_TYPES[element['type']]['name']}")
                        st.write(f"**Description:** {element['description'] or 'No description provided'}")
                    
                    with col2:
                        st.write(f"**Authentication:** {element['properties']['authentication'] or 'Not specified'}")
                        st.write(f"**Encryption:** {element['properties']['encryption'] or 'Not specified'}")
        else:
            st.info("👈 Use the sidebar to add elements to your system design.")
    
    with tab2:
        render_threat_analysis()
        if st.session_state.threat_model:
            render_threat_details()
    
    with tab3:
        render_dashboard()
    
    with tab4:
        render_export_section()

if __name__ == "__main__":
    main()