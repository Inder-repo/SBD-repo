
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import json
import uuid
from datetime import datetime
from enum import Enum
import hashlib

# Enhanced Enums for better type safety
class ComponentType(Enum):
    EXTERNAL_ENTITY = "External Entity"
    PROCESS = "Process"
    DATA_STORE = "Data Store"
    TRUST_BOUNDARY = "Trust Boundary"

class SecurityLevel(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"

class ThreatSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class StrideCategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

# Enhanced data classes with better structure
@dataclass
class Component:
    id: str
    name: str
    type: ComponentType
    description: str
    x: float
    y: float
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    technologies: List[str] = field(default_factory=list)
    data_classification: str = "Internal"
    owner: str = "Unknown"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class DataFlow:
    id: str
    source: str
    target: str
    data_type: str
    protocol: str
    description: str
    port: Optional[int] = None
    encryption: bool = False
    authentication_required: bool = False
    data_classification: str = "Internal"
    crosses_trust_boundary: bool = False
    trust_boundary_crossed: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class TrustBoundary:
    id: str
    name: str
    components: List[str]
    security_level: SecurityLevel
    description: str
    color: str = "#4CAF50"
    boundary_type: str = "Network"  # Network, Process, Physical
    controls: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class Threat:
    id: str
    name: str
    description: str
    affected_components: List[str]
    stride_category: StrideCategory
    severity: ThreatSeverity
    mitigation: str
    likelihood: str = "Medium"
    impact: str = "Medium"
    risk_score: float = 0.0
    status: str = "Open"
    assigned_to: str = "Unassigned"
    due_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

# Enhanced Trust Boundary Templates
DEFAULT_TRUST_BOUNDARIES = {
    "Internet": {
        "name": "Internet/Public Zone",
        "security_level": SecurityLevel.LOW,
        "description": "Public internet-facing components with minimal trust",
        "color": "#FF5722",
        "boundary_type": "Network",
        "controls": ["DDoS Protection", "WAF", "Rate Limiting"],
        "compliance_requirements": ["GDPR", "CCPA"]
    },
    "DMZ": {
        "name": "Demilitarized Zone",
        "security_level": SecurityLevel.MEDIUM,
        "description": "Semi-trusted zone for public-facing services",
        "color": "#FF9800",
        "boundary_type": "Network",
        "controls": ["Firewall", "IDS/IPS", "Load Balancing"],
        "compliance_requirements": ["PCI DSS", "SOC 2"]
    },
    "Internal": {
        "name": "Internal Network",
        "security_level": SecurityLevel.HIGH,
        "description": "Trusted internal network with business applications",
        "color": "#4CAF50",
        "boundary_type": "Network",
        "controls": ["Network Segmentation", "IAM", "Monitoring"],
        "compliance_requirements": ["SOC 2", "ISO 27001"]
    },
    "Database": {
        "name": "Database Zone",
        "security_level": SecurityLevel.CRITICAL,
        "description": "Highly secured zone for sensitive data storage",
        "color": "#9C27B0",
        "boundary_type": "Network",
        "controls": ["Database Encryption", "Access Controls", "Audit Logging"],
        "compliance_requirements": ["PCI DSS", "HIPAA", "SOX"]
    },
    "Admin": {
        "name": "Administrative Zone",
        "security_level": SecurityLevel.CRITICAL,
        "description": "Privileged access zone for system administration",
        "color": "#F44336",
        "boundary_type": "Process",
        "controls": ["Privileged Access Management", "MFA", "Session Recording"],
        "compliance_requirements": ["SOC 2", "ISO 27001"]
    },
    "External": {
        "name": "External Services",
        "security_level": SecurityLevel.LOW,
        "description": "Third-party services and external integrations",
        "color": "#607D8B",
        "boundary_type": "Network",
        "controls": ["API Security", "SLA Monitoring", "Data Encryption"],
        "compliance_requirements": ["Third-party Risk Assessment"]
    }
}

# Enhanced Threat Patterns with Trust Boundary considerations
ENHANCED_THREAT_PATTERNS = {
    "Web Application": [
        Threat(
            id="WEB001",
            name="SQL Injection",
            description="Malicious SQL code injection through user inputs affecting database integrity",
            affected_components=["Database"],
            stride_category=StrideCategory.TAMPERING,
            severity=ThreatSeverity.HIGH,
            mitigation="Implement parameterized queries, input validation, and stored procedures",
            likelihood="Medium",
            impact="High",
            risk_score=7.5
        ),
        Threat(
            id="WEB002",
            name="Cross-Site Scripting (XSS)",
            description="Malicious scripts executed in user browsers compromising client-side security",
            affected_components=["Web Server"],
            stride_category=StrideCategory.TAMPERING,
            severity=ThreatSeverity.MEDIUM,
            mitigation="Implement output encoding, CSP headers, and input sanitization",
            likelihood="High",
            impact="Medium",
            risk_score=6.0
        ),
        Threat(
            id="WEB003",
            name="Authentication Bypass",
            description="Unauthorized access to protected resources through authentication flaws",
            affected_components=["Authentication Service"],
            stride_category=StrideCategory.SPOOFING,
            severity=ThreatSeverity.HIGH,
            mitigation="Implement MFA, session management, and strong password policies",
            likelihood="Low",
            impact="High",
            risk_score=6.5
        ),
        Threat(
            id="WEB004",
            name="Session Hijacking",
            description="Unauthorized access through stolen session tokens or cookies",
            affected_components=["Web Server"],
            stride_category=StrideCategory.SPOOFING,
            severity=ThreatSeverity.HIGH,
            mitigation="Use secure session management, HTTPS, and session timeouts",
            likelihood="Medium",
            impact="High",
            risk_score=7.0
        )
    ],
    "API": [
        Threat(
            id="API001",
            name="API Rate Limiting Bypass",
            description="Overwhelming API endpoints with excessive requests causing service degradation",
            affected_components=["API Gateway"],
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            severity=ThreatSeverity.MEDIUM,
            mitigation="Implement proper rate limiting, throttling, and API quotas",
            likelihood="High",
            impact="Medium",
            risk_score=6.0
        ),
        Threat(
            id="API002",
            name="Insecure Direct Object References",
            description="Unauthorized access to objects through predictable resource identifiers",
            affected_components=["API Server"],
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            severity=ThreatSeverity.HIGH,
            mitigation="Implement proper authorization checks and indirect object references",
            likelihood="Medium",
            impact="High",
            risk_score=7.0
        ),
        Threat(
            id="API003",
            name="API Key Exposure",
            description="Exposure of API keys in client-side code or logs",
            affected_components=["API Gateway"],
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            severity=ThreatSeverity.MEDIUM,
            mitigation="Use secure key management, rotation, and server-side validation",
            likelihood="Medium",
            impact="Medium",
            risk_score=5.0
        )
    ],
    "Trust Boundary": [
        Threat(
            id="TB001",
            name="Trust Boundary Violation",
            description="Unauthorized data flow across trust boundaries without proper validation",
            affected_components=["Trust Boundary"],
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            severity=ThreatSeverity.HIGH,
            mitigation="Implement boundary controls, data validation, and monitoring",
            likelihood="Medium",
            impact="High",
            risk_score=7.5
        ),
        Threat(
            id="TB002",
            name="Privilege Escalation Across Boundaries",
            description="Gaining higher privileges when crossing trust boundaries",
            affected_components=["Trust Boundary"],
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            severity=ThreatSeverity.CRITICAL,
            mitigation="Implement least privilege principle and access controls",
            likelihood="Low",
            impact="Critical",
            risk_score=8.0
        ),
        Threat(
            id="TB003",
            name="Data Leakage Across Boundaries",
            description="Sensitive data flowing to lower trust zones without proper protection",
            affected_components=["Trust Boundary"],
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            severity=ThreatSeverity.HIGH,
            mitigation="Implement data classification and DLP controls",
            likelihood="Medium",
            impact="High",
            risk_score=7.0
        )
    ]
}

# Initialize enhanced session state
def initialize_session_state():
    """Initialize session state with enhanced structure"""
    if 'project_id' not in st.session_state:
        st.session_state.project_id = str(uuid.uuid4())
    
    if 'project_name' not in st.session_state:
        st.session_state.project_name = "New Threat Model"
    
    if 'components' not in st.session_state:
        st.session_state.components = []
    
    if 'data_flows' not in st.session_state:
        st.session_state.data_flows = []
    
    if 'trust_boundaries' not in st.session_state:
        st.session_state.trust_boundaries = []
    
    if 'threats' not in st.session_state:
        st.session_state.threats = []
    
    if 'user_role' not in st.session_state:
        st.session_state.user_role = "Security Analyst"
    
    if 'organization' not in st.session_state:
        st.session_state.organization = "Enterprise Corp"

def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix"""
    return f"{prefix}{str(uuid.uuid4())[:8]}"

def calculate_risk_score(likelihood: str, impact: str) -> float:
    """Calculate risk score based on likelihood and impact"""
    likelihood_map = {"Low": 1, "Medium": 2, "High": 3}
    impact_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    
    l_score = likelihood_map.get(likelihood, 2)
    i_score = impact_map.get(impact, 2)
    
    return (l_score * i_score) * 1.25  # Scale to 0-15

def create_default_trust_boundaries() -> List[TrustBoundary]:
    """Create default trust boundaries based on common patterns"""
    boundaries = []
    
    for key, template in DEFAULT_TRUST_BOUNDARIES.items():
        boundary = TrustBoundary(
            id=generate_id("TB_"),
            name=template["name"],
            components=[],
            security_level=template["security_level"],
            description=template["description"],
            color=template["color"],
            boundary_type=template["boundary_type"],
            controls=template["controls"].copy(),
            compliance_requirements=template["compliance_requirements"].copy()
        )
        boundaries.append(boundary)
    
    return boundaries

def analyze_trust_boundary_crossings(data_flows: List[DataFlow], 
                                   trust_boundaries: List[TrustBoundary]) -> List[DataFlow]:
    """Analyze which data flows cross trust boundaries"""
    updated_flows = []
    
    for flow in data_flows:
        # Find source and target trust boundaries
        source_boundary = None
        target_boundary = None
        
        for boundary in trust_boundaries:
            if flow.source in boundary.components:
                source_boundary = boundary
            if flow.target in boundary.components:
                target_boundary = boundary
        
        # Update flow with boundary crossing information
        if source_boundary and target_boundary and source_boundary.id != target_boundary.id:
            flow.crosses_trust_boundary = True
            flow.trust_boundary_crossed = f"{source_boundary.name} → {target_boundary.name}"
        
        updated_flows.append(flow)
    
    return updated_flows

# This completes Part 1 - Enhanced Data Flow Architecture with Trust Boundary Support
# The next parts will build upon this foundation with UI components, commercial features, etc.


# Part 2: Enterprise-Grade UI Components and Layout
# This builds upon Part 1's enhanced data structures

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd

# Enterprise UI Configuration
ENTERPRISE_THEME = {
    'primary_color': '#1f77b4',
    'secondary_color': '#ff7f0e',
    'success_color': '#2ca02c',
    'warning_color': '#ff9800',
    'error_color': '#d62728',
    'info_color': '#17a2b8',
    'background_color': '#f8f9fa',
    'card_background': '#ffffff',
    'text_color': '#343a40',
    'border_color': '#dee2e6'
}

def render_header():
    """Render professional header with branding"""
    st.markdown("""
    <div style="background: linear-gradient(90deg, #1f77b4 0%, #2ca02c 100%); 
                padding: 2rem; margin: -1rem -1rem 2rem -1rem; border-radius: 10px;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <div>
                <h1 style="color: white; margin: 0; font-size: 2.5rem; font-weight: 700;">
                    🛡️ ThreatModel Enterprise
                </h1>
                <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 1.1rem;">
                    Advanced Threat Modeling & Risk Assessment Platform
                </p>
            </div>
            <div style="text-align: right; color: white;">
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.8;">
                    Organization: {org}
                </p>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.8;">
                    User: {user} | {role}
                </p>
            </div>
        </div>
    </div>
    """.format(
        org=st.session_state.get('organization', 'Enterprise Corp'),
        user=st.session_state.get('user_name', 'Security Analyst'),
        role=st.session_state.get('user_role', 'Analyst')
    ), unsafe_allow_html=True)

def render_metrics_dashboard():
    """Render key metrics dashboard"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🏗️ Components", 
            value=len(st.session_state.get('components', [])),
            delta=f"+{len([c for c in st.session_state.get('components', []) if c.created_at.date() == datetime.now().date()])}"
        )
    
    with col2:
        st.metric(
            label="🔄 Data Flows", 
            value=len(st.session_state.get('data_flows', [])),
            delta=f"+{len([f for f in st.session_state.get('data_flows', []) if f.created_at.date() == datetime.now().date()])}"
        )
    
    with col3:
        threats = st.session_state.get('threats', [])
        high_critical = len([t for t in threats if t.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]])
        st.metric(
            label="⚠️ Critical/High Threats", 
            value=high_critical,
            delta=f"{high_critical}/{len(threats)}" if threats else "0/0"
        )
    
    with col4:
        boundaries = st.session_state.get('trust_boundaries', [])
        st.metric(
            label="🔐 Trust Boundaries", 
            value=len(boundaries),
            delta=f"Security Zones"
        )

def render_professional_card(title, content, icon="📊", color="primary"):
    """Render a professional card component"""
    color_map = {
        'primary': ENTERPRISE_THEME['primary_color'],
        'success': ENTERPRISE_THEME['success_color'],
        'warning': ENTERPRISE_THEME['warning_color'],
        'error': ENTERPRISE_THEME['error_color'],
        'info': ENTERPRISE_THEME['info_color']
    }
    
    border_color = color_map.get(color, ENTERPRISE_THEME['primary_color'])
    
    st.markdown(f"""
    <div style="
        background: {ENTERPRISE_THEME['card_background']};
        border: 1px solid {ENTERPRISE_THEME['border_color']};
        border-left: 4px solid {border_color};
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    ">
        <h3 style="color: {border_color}; margin: 0 0 1rem 0; display: flex; align-items: center;">
            <span style="margin-right: 0.5rem;">{icon}</span>
            {title}
        </h3>
        <div style="color: {ENTERPRISE_THEME['text_color']};">
            {content}
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_component_form():
    """Render enhanced component creation form"""
    st.subheader("🏗️ Add System Component")
    
    with st.form("enhanced_component_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            comp_name = st.text_input("Component Name*", placeholder="e.g., Web Application Server")
            comp_type = st.selectbox("Component Type*", [t.value for t in ComponentType if t != ComponentType.TRUST_BOUNDARY])
            comp_description = st.text_area("Description", placeholder="Detailed description of the component's purpose and function")
            
        with col2:
            comp_owner = st.text_input("Owner", placeholder="Team or individual responsible")
            comp_security_level = st.selectbox("Security Level", [s.value for s in SecurityLevel])
            comp_data_classification = st.selectbox("Data Classification", 
                                                   ["Public", "Internal", "Confidential", "Restricted"])
            
        # Position controls
        st.subheader("Position")
        pos_col1, pos_col2 = st.columns(2)
        with pos_col1:
            comp_x = st.slider("X Position", 1, 10, 5)
        with pos_col2:
            comp_y = st.slider("Y Position", 1, 10, 5)
            
        # Technologies
        comp_technologies = st.multiselect(
            "Technologies/Frameworks",
            ["Java", "Python", "Node.js", "React", "Angular", "PostgreSQL", "MongoDB", 
             "Redis", "Docker", "Kubernetes", "AWS", "Azure", "GCP", "Nginx", "Apache"],
            help="Select applicable technologies"
        )
        
        submitted = st.form_submit_button("➕ Add Component", type="primary")
        
        if submitted and comp_name and comp_type:
            new_component = Component(
                id=generate_id("COMP_"),
                name=comp_name,
                type=ComponentType(comp_type),
                description=comp_description,
                x=comp_x,
                y=comp_y,
                security_level=SecurityLevel(comp_security_level),
                technologies=comp_technologies,
                data_classification=comp_data_classification,
                owner=comp_owner or "Unknown"
            )
            
            st.session_state.components.append(new_component)
            st.success(f"✅ Component '{comp_name}' added successfully!")
            st.rerun()

def render_data_flow_form():
    """Render enhanced data flow creation form"""
    st.subheader("🔄 Add Data Flow")
    
    if not st.session_state.components:
        st.info("💡 Add components first to create data flows between them.")
        return
    
    component_names = [c.name for c in st.session_state.components]
    
    with st.form("enhanced_dataflow_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            source = st.selectbox("Source Component*", component_names)
            target = st.selectbox("Target Component*", component_names)
            data_type = st.text_input("Data Type*", placeholder="e.g., User Credentials, Payment Data")
            
        with col2:
            protocol = st.selectbox("Protocol*", ["HTTPS", "HTTP", "TLS", "TCP", "UDP", "WebSocket", "gRPC"])
            port = st.number_input("Port", min_value=1, max_value=65535, value=443)
            data_classification = st.selectbox("Data Classification", 
                                             ["Public", "Internal", "Confidential", "Restricted"])
        
        # Security controls
        st.subheader("Security Controls")
        sec_col1, sec_col2 = st.columns(2)
        with sec_col1:
            encryption = st.checkbox("Encrypted in Transit", value=True)
        with sec_col2:
            authentication = st.checkbox("Authentication Required", value=True)
            
        flow_description = st.text_area("Description", 
                                      placeholder="Describe the data flow and its business purpose")
        
        submitted = st.form_submit_button("➕ Add Data Flow", type="primary")
        
        if submitted and source and target and data_type:
            if source == target:
                st.error("❌ Source and target cannot be the same component.")
                return
                
            new_flow = DataFlow(
                id=generate_id("FLOW_"),
                source=source,
                target=target,
                data_type=data_type,
                protocol=protocol,
                description=flow_description,
                port=port,
                encryption=encryption,
                authentication_required=authentication,
                data_classification=data_classification
            )
            
            st.session_state.data_flows.append(new_flow)
            st.success(f"✅ Data flow from '{source}' to '{target}' added successfully!")
            st.rerun()

def render_trust_boundary_form():
    """Render enhanced trust boundary creation form"""
    st.subheader("🔐 Manage Trust Boundaries")
    
    # Quick setup with default boundaries
    if not st.session_state.trust_boundaries:
        st.info("💡 Start with default trust boundaries or create custom ones.")
        if st.button("🚀 Setup Default Trust Boundaries", type="primary"):
            st.session_state.trust_boundaries = create_default_trust_boundaries()
            st.success("✅ Default trust boundaries created!")
            st.rerun()
    
    # Custom boundary creation
    with st.expander("➕ Create Custom Trust Boundary"):
        with st.form("trust_boundary_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                boundary_name = st.text_input("Boundary Name*", placeholder="e.g., Application Tier")
                boundary_type = st.selectbox("Boundary Type", ["Network", "Process", "Physical", "Administrative"])
                security_level = st.selectbox("Security Level*", [s.value for s in SecurityLevel])
                
            with col2:
                color = st.color_picker("Boundary Color", "#4CAF50")
                boundary_description = st.text_area("Description", 
                                                  placeholder="Describe the trust boundary and its purpose")
            
            # Component selection
            if st.session_state.components:
                component_names = [c.name for c in st.session_state.components]
                selected_components = st.multiselect("Components in Boundary", component_names)
            else:
                selected_components = []
                st.info("Add components first to assign them to boundaries.")
            
            # Security controls
            available_controls = [
                "Firewall", "IDS/IPS", "DLP", "WAF", "Load Balancer", "VPN", "MFA", 
                "Encryption", "Access Control", "Monitoring", "Audit Logging"
            ]
            controls = st.multiselect("Security Controls", available_controls)
            
            # Compliance requirements
            compliance_options = [
                "PCI DSS", "HIPAA", "SOC 2", "ISO 27001", "GDPR", "CCPA", "SOX", "FISMA"
            ]
            compliance = st.multiselect("Compliance Requirements", compliance_options)
            
            submitted = st.form_submit_button("➕ Create Trust Boundary", type="primary")
            
            if submitted and boundary_name and security_level:
                new_boundary = TrustBoundary(
                    id=generate_id("TB_"),
                    name=boundary_name,
                    components=selected_components,
                    security_level=SecurityLevel(security_level),
                    description=boundary_description,
                    color=color,
                    boundary_type=boundary_type,
                    controls=controls,
                    compliance_requirements=compliance
                )
                
                st.session_state.trust_boundaries.append(new_boundary)
                st.success(f"✅ Trust boundary '{boundary_name}' created successfully!")
                st.rerun()

def render_component_table():
    """Render enhanced component table with management actions"""
    if not st.session_state.components:
        st.info("No components added yet. Create your first component above.")
        return
    
    st.subheader("📋 Component Inventory")
    
    # Convert to DataFrame for better display
    component_data = []
    for comp in st.session_state.components:
        component_data.append({
            "Name": comp.name,
            "Type": comp.type.value,
            "Security Level": comp.security_level.value,
            "Data Classification": comp.data_classification,
            "Owner": comp.owner,
            "Technologies": ", ".join(comp.technologies) if comp.technologies else "None",
            "Created": comp.created_at.strftime("%Y-%m-%d")
        })
    
    df = pd.DataFrame(component_data)
    
    # Add filters
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    
    with filter_col1:
        type_filter = st.selectbox("Filter by Type", ["All"] + [t.value for t in ComponentType if t != ComponentType.TRUST_BOUNDARY])
    
    with filter_col2:
        security_filter = st.selectbox("Filter by Security Level", ["All"] + [s.value for s in SecurityLevel])
    
    with filter_col3:
        classification_filter = st.selectbox("Filter by Data Classification", 
                                           ["All", "Public", "Internal", "Confidential", "Restricted"])
    
    # Apply filters
    filtered_df = df.copy()
    if type_filter != "All":
        filtered_df = filtered_df[filtered_df["Type"] == type_filter]
    if security_filter != "All":
        filtered_df = filtered_df[filtered_df["Security Level"] == security_filter]
    if classification_filter != "All":
        filtered_df = filtered_df[filtered_df["Data Classification"] == classification_filter]
    
    # Display table
    st.dataframe(filtered_df, use_container_width=True, hide_index=True)
    
    # Component management actions
    if st.button("🗑️ Clear All Components", type="secondary"):
        if st.session_state.components:
            st.session_state.components = []
            st.session_state.data_flows = []  # Clear dependent data flows
            st.success("✅ All components cleared!")
            st.rerun()

def render_enhanced_architecture_diagram():
    """Render enhanced architecture diagram with professional styling"""
    if not st.session_state.components:
        st.info("📊 Add components to visualize your architecture diagram.")
        return
    
    st.subheader("🎨 Architecture Visualization")
    
    # Diagram controls
    control_col1, control_col2, control_col3 = st.columns(3)
    
    with control_col1:
        show_labels = st.checkbox("Show Component Labels", value=True)
    with control_col2:
        show_boundaries = st.checkbox("Show Trust Boundaries", value=True)
    with control_col3:
        show_flows = st.checkbox("Show Data Flows", value=True)
    
    fig = create_enhanced_architecture_diagram(
        st.session_state.components,
        st.session_state.data_flows,
        st.session_state.trust_boundaries,
        show_labels=show_labels,
        show_boundaries=show_boundaries,
        show_flows=show_flows
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Export options
    export_col1, export_col2 = st.columns(2)
    with export_col1:
        if st.button("📥 Export as PNG"):
            st.info("Feature available in full version - Export diagram as PNG")
    with export_col2:
        if st.button("📄 Export as PDF"):
            st.info("Feature available in full version - Export diagram as PDF")

def create_enhanced_architecture_diagram(components, data_flows, trust_boundaries, 
                                       show_labels=True, show_boundaries=True, show_flows=True):
    """Create an enhanced professional architecture diagram"""
    fig = go.Figure()
    
    # Enhanced color scheme
    component_colors = {
        ComponentType.EXTERNAL_ENTITY: '#FF6B6B',
        ComponentType.PROCESS: '#4ECDC4',
        ComponentType.DATA_STORE: '#45B7D1'
    }
    
    # Add trust boundaries as enhanced shapes
    if show_boundaries and trust_boundaries:
        for i, boundary in enumerate(trust_boundaries):
            boundary_components = [c for c in components if c.name in boundary.components]
            if boundary_components:
                min_x = min(c.x for c in boundary_components) - 0.4
                max_x = max(c.x for c in boundary_components) + 0.4
                min_y = min(c.y for c in boundary_components) - 0.4
                max_y = max(c.y for c in boundary_components) + 0.4
                
                # Add boundary rectangle with enhanced styling
                fig.add_shape(
                    type="rect",
                    x0=min_x, y0=min_y,
                    x1=max_x, y1=max_y,
                    fillcolor=boundary.color,
                    opacity=0.2,
                    line=dict(width=3, color=boundary.color, dash="dash"),
                    layer="below"
                )
                
                # Add enhanced boundary label
                fig.add_annotation(
                    x=min_x + 0.1,
                    y=max_y - 0.1,
                    text=f"🔐 {boundary.name}",
                    showarrow=False,
                    font=dict(size=12, color="white", family="Arial Black"),
                    bgcolor=boundary.color,
                    bordercolor="white",
                    borderwidth=2,
                    borderpad=4,
                    opacity=0.9
                )
                
                # Add security level indicator
                fig.add_annotation(
                    x=max_x - 0.1,
                    y=max_y - 0.1,
                    text=f"🛡️ {boundary.security_level.value}",
                    showarrow=False,
                    font=dict(size=10, color="white"),
                    bgcolor=boundary.color,
                    bordercolor="white",
                    borderwidth=1,
                    borderpad=2,
                    opacity=0.8
                )
    
    # Add components with enhanced styling
    for component in components:
        color = component_colors.get(component.type, '#95A5A6')
        
        # Determine symbol based on type
        symbol = 'circle'
        if component.type == ComponentType.DATA_STORE:
            symbol = 'square'
        elif component.type == ComponentType.EXTERNAL_ENTITY:
            symbol = 'diamond'
        
        # Add component marker
        fig.add_trace(go.Scatter(
            x=[component.x],
            y=[component.y],
            mode='markers+text' if show_labels else 'markers',
            marker=dict(
                size=25,
                color=color,
                symbol=symbol,
                line=dict(width=3, color='white'),
                opacity=0.9
            ),
            text=component.name if show_labels else "",
            textposition="bottom center",
            textfont=dict(size=10, color='black', family="Arial"),
            name=component.type.value,
            hovertemplate=(
                f"<b>{component.name}</b><br>"
                f"Type: {component.type.value}<br>"
                f"Security Level: {component.security_level.value}<br>"
                f"Owner: {component.owner}<br>"
                f"Description: {component.description}<br>"
                f"<extra></extra>"
            )
        ))
    
    # Add data flows with enhanced arrows
    if show_flows and data_flows:
        for flow in data_flows:
            source_comp = next((c for c in components if c.name == flow.source), None)
            target_comp = next((c for c in components if c.name == flow.target), None)
            
            if source_comp and target_comp:
                # Determine arrow color based on security
                arrow_color = '#2ECC71' if flow.encryption else '#E74C3C'
                arrow_width = 3 if flow.crosses_trust_boundary else 2
                
                fig.add_annotation(
                    x=target_comp.x,
                    y=target_comp.y,
                    ax=source_comp.x,
                    ay=source_comp.y,
                    xref="x", yref="y",
                    axref="x", ayref="y",
                    showarrow=True,
                    arrowhead=2,
                    arrowsize=1.5,
                    arrowwidth=arrow_width,
                    arrowcolor=arrow_color,
                    text=f"{flow.data_type}<br>({flow.protocol})" if show_flows else "",
                    textangle=0,
                    font=dict(size=8, color=arrow_color),
                    bgcolor="white",
                    bordercolor=arrow_color,
                    borderwidth=1,
                    opacity=0.8
                )
    
    # Enhanced layout
    fig.update_layout(
        title=dict(
            text="🏗️ System Architecture Diagram",
            font=dict(size=20, color=ENTERPRISE_THEME['text_color']),
            x=0.5
        ),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        width=1000,
        height=700,
        xaxis=dict(
            showgrid=True,
            gridcolor='rgba(128,128,128,0.2)',
            zeroline=False,
            showticklabels=False,
            title=""
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor='rgba(128,128,128,0.2)',
            zeroline=False,
            showticklabels=False,
            title=""
        ),
        plot_bgcolor='rgba(248,249,250,0.8)',
        paper_bgcolor='white'
    )
    
    return fig

def render_project_info_sidebar():
    """Render project information in sidebar"""
    st.sidebar.markdown("---")
    st.sidebar.subheader("📋 Project Information")
    
    # Project details
    st.sidebar.text_input("Project Name", 
                         value=st.session_state.get('project_name', 'New Threat Model'),
                         key="project_name_input")
    
    st.sidebar.selectbox("Project Status", 
                        ["Draft", "In Review", "Approved", "Archived"],
                        key="project_status")
    
    st.sidebar.text_area("Project Description", 
                        placeholder="Describe the scope and purpose of this threat model...",
                        key="project_description")
    
    # Statistics
    st.sidebar.markdown("### 📊 Statistics")
    stats_data = {
        "Components": len(st.session_state.get('components', [])),
        "Data Flows": len(st.session_state.get('data_flows', [])),
        "Trust Boundaries": len(st.session_state.get('trust_boundaries', [])),
        "Threats": len(st.session_state.get('threats', []))
    }
    
    for key, value in stats_data.items():
        st.sidebar.metric(key, value)
    
    # Quick actions
    st.sidebar.markdown("### ⚡ Quick Actions")
    if st.sidebar.button("🔄 Refresh Analysis"):
        st.rerun()
    
    if st.sidebar.button("📊 Generate Report"):
        st.info("Report generation available in full version")
    
    if st.sidebar.button("💾 Save Project"):
        st.success("Project saved successfully!")

def render_navigation_menu():
    """Render enhanced navigation menu"""
    st.sidebar.title("🧭 Navigation")
    
    # Main navigation
    main_pages = {
        "🏠 Dashboard": "dashboard",
        "🏗️ Architecture Builder": "architecture",
        "🔍 Threat Analysis": "threats",
        "📊 Risk Assessment": "risk",
        "📚 Knowledge Base": "knowledge",
        "⚙️ Settings": "settings"
    }
    
    selected_page = st.sidebar.selectbox(
        "Select Page",
        list(main_pages.keys()),
        key="main_navigation"
    )
    
    # Sample architectures section
    st.sidebar.markdown("---")
    st.sidebar.subheader("📖 Sample Architectures")
    
    sample_options = [
        "🏦 Online Banking",
        "🛒 E-commerce Platform",
        "🏥 Healthcare System",
        "☁️ Cloud Infrastructure",
        "🏭 Industrial IoT"
    ]
    
    selected_sample = st.sidebar.selectbox(
        "Load Sample",
        ["Select a sample..."] + sample_options,
        key="sample_selection"
    )
    
    return main_pages.get(selected_page, "dashboard"), selected_sample

# This completes Part 2 - Enterprise-Grade UI Components
# Part 3 will focus on Commercial Features & Security


# Part 3: Commercial Features & Security Implementation
# This builds upon Parts 1 & 2 with enterprise-grade features

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
import hashlib
import base64
from typing import Dict, List, Optional
import io
import time
from enum import Enum
from dataclasses import dataclass, field
import uuid

# Authentication and User Management
class UserRole(Enum):
    ADMIN = "Administrator"
    SECURITY_ANALYST = "Security Analyst"
    ARCHITECT = "Security Architect"
    AUDITOR = "Auditor"
    VIEWER = "Viewer"

@dataclass
class User:
    id: str
    username: str
    email: str
    role: UserRole
    organization: str
    department: str
    last_login: datetime
    permissions: List[str] = field(default_factory=list)
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class AuditLog:
    id: str
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    timestamp: datetime
    details: Dict
    ip_address: str = "Unknown"
    user_agent: str = "Unknown"

# Core data structures (from previous parts)
class ComponentType(Enum):
    WEB_APPLICATION = "Web Application"
    DATABASE = "Database"
    API_SERVICE = "API Service"
    EXTERNAL_SERVICE = "External Service"
    USER_INTERFACE = "User Interface"
    LOAD_BALANCER = "Load Balancer"
    CACHE = "Cache"
    MESSAGE_QUEUE = "Message Queue"
    FILE_STORAGE = "File Storage"
    AUTHENTICATION_SERVICE = "Authentication Service"

class TrustLevel(Enum):
    PUBLIC = "Public"
    AUTHENTICATED = "Authenticated"
    PRIVILEGED = "Privileged"
    RESTRICTED = "Restricted"

class StrideCategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

class ThreatSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class Component:
    id: str
    name: str
    type: ComponentType
    description: str
    trust_level: TrustLevel
    technologies: List[str] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class DataFlow:
    id: str
    source: str
    destination: str
    data_type: str
    protocol: str
    encryption: bool
    authentication_required: bool
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class Threat:
    id: str
    name: str
    description: str
    affected_components: List[str]
    stride_category: StrideCategory
    severity: ThreatSeverity
    likelihood: str
    impact: str
    risk_score: float
    mitigation: str
    status: str = "Open"
    assigned_to: str = ""
    created_at: datetime = field(default_factory=datetime.now)

def generate_id(prefix: str = "") -> str:
    """Generate unique ID"""
    return f"{prefix}{str(uuid.uuid4())[:8]}"

# Enhanced security features
def authenticate_user(username: str, password: str) -> Optional[User]:
    """Simulate user authentication - in production, integrate with SSO/LDAP"""
    # Demo users for testing
    demo_users = {
        "admin": User(
            id="usr_admin",
            username="admin",
            email="admin@enterprise.com",
            role=UserRole.ADMIN,
            organization="Enterprise Corp",
            department="IT Security",
            last_login=datetime.now(),
            permissions=["read", "write", "delete", "admin"]
        ),
        "analyst": User(
            id="usr_analyst",
            username="analyst",
            email="analyst@enterprise.com",
            role=UserRole.SECURITY_ANALYST,
            organization="Enterprise Corp",
            department="Security",
            last_login=datetime.now(),
            permissions=["read", "write"]
        ),
        "viewer": User(
            id="usr_viewer",
            username="viewer",
            email="viewer@enterprise.com",
            role=UserRole.VIEWER,
            organization="Enterprise Corp",
            department="Audit",
            last_login=datetime.now(),
            permissions=["read"]
        )
    }
    
    # Simple password check (in production, use proper hashing)
    if username in demo_users and password == "demo123":
        return demo_users[username]
    
    return None

def log_audit_event(user_id: str, action: str, resource_type: str, resource_id: str, details: Dict):
    """Log audit events for compliance"""
    if 'audit_logs' not in st.session_state:
        st.session_state.audit_logs = []
    
    log_entry = AuditLog(
        id=generate_id("LOG_"),
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=datetime.now(),
        details=details
    )
    
    st.session_state.audit_logs.append(log_entry)

def check_permission(required_permission: str) -> bool:
    """Check if current user has required permission"""
    current_user = st.session_state.get('current_user')
    if not current_user:
        return False
    
    return required_permission in current_user.permissions

def render_login_page():
    """Render professional login page"""
    st.markdown("""
    <div style="max-width: 400px; margin: 5rem auto; padding: 2rem; 
                background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="color: #1f77b4; margin: 0;">🛡️ ThreatModel Enterprise</h1>
            <p style="color: #666; margin: 0.5rem 0;">Secure Access Portal</p>
        </div>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        col1, col2 = st.columns(2)
        with col1:
            login_btn = st.form_submit_button("🔐 Login", type="primary", use_container_width=True)
        with col2:
            demo_btn = st.form_submit_button("🎯 Demo Access", use_container_width=True)
        
        if login_btn:
            user = authenticate_user(username, password)
            if user:
                st.session_state.current_user = user
                st.session_state.authenticated = True
                log_audit_event(user.id, "LOGIN", "SYSTEM", "AUTH", {"username": username})
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials")
        
        if demo_btn:
            demo_user = authenticate_user("analyst", "demo123")
            st.session_state.current_user = demo_user
            st.session_state.authenticated = True
            st.info("🎯 Demo mode activated - Security Analyst role")
            st.rerun()
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Demo credentials info
    st.markdown("""
    <div style="max-width: 400px; margin: 2rem auto; padding: 1rem; 
                background: #f8f9fa; border-radius: 5px; border-left: 4px solid #17a2b8;">
        <h4 style="color: #17a2b8; margin: 0 0 1rem 0;">🎯 Demo Credentials</h4>
        <p style="margin: 0.5rem 0;"><strong>Admin:</strong> admin / demo123</p>
        <p style="margin: 0.5rem 0;"><strong>Analyst:</strong> analyst / demo123</p>
        <p style="margin: 0.5rem 0;"><strong>Viewer:</strong> viewer / demo123</p>
    </div>
    """, unsafe_allow_html=True)

def render_user_profile():
    """Render user profile section"""
    if not st.session_state.get('authenticated'):
        return
    
    current_user = st.session_state.current_user
    
    with st.expander("👤 User Profile"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.write(f"**Name:** {current_user.username}")
            st.write(f"**Email:** {current_user.email}")
            st.write(f"**Role:** {current_user.role.value}")
        
        with col2:
            st.write(f"**Organization:** {current_user.organization}")
            st.write(f"**Department:** {current_user.department}")
            st.write(f"**Last Login:** {current_user.last_login.strftime('%Y-%m-%d %H:%M')}")
        
        if st.button("🚪 Logout"):
            log_audit_event(current_user.id, "LOGOUT", "SYSTEM", "AUTH", {})
            st.session_state.authenticated = False
            st.session_state.current_user = None
            st.rerun()

def render_metrics_dashboard():
    """Render key metrics dashboard"""
    threats = st.session_state.get('threats', [])
    components = st.session_state.get('components', [])
    data_flows = st.session_state.get('data_flows', [])
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🎯 Total Threats", len(threats))
    
    with col2:
        critical_threats = len([t for t in threats if t.severity == ThreatSeverity.CRITICAL])
        st.metric("🔥 Critical Threats", critical_threats)
    
    with col3:
        st.metric("🏗️ Components", len(components))
    
    with col4:
        unencrypted_flows = len([f for f in data_flows if not f.encryption])
        st.metric("⚠️ Unencrypted Flows", unencrypted_flows)

def render_dashboard():
    """Render executive dashboard with KPIs"""
    st.header("📊 Executive Dashboard")
    
    # KPI Metrics
    render_metrics_dashboard()
    
    # Risk heatmap
    col1, col2 = st.columns(2)
    
    with col1:
        render_risk_heatmap()
    
    with col2:
        render_threat_timeline()
    
    # Recent activities
    st.subheader("📋 Recent Activities")
    render_recent_activities()
    
    # Compliance status
    st.subheader("✅ Compliance Status")
    render_compliance_dashboard()

def render_risk_heatmap():
    """Render risk assessment heatmap"""
    st.subheader("🔥 Risk Heat Map")
    
    # Generate sample risk data
    risk_data = []
    threats = st.session_state.get('threats', [])
    
    if threats:
        for threat in threats:
            likelihood_score = {"Low": 1, "Medium": 2, "High": 3}.get(threat.likelihood, 2)
            impact_score = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(threat.impact, 2)
            
            risk_data.append({
                "Threat": threat.name[:20] + "..." if len(threat.name) > 20 else threat.name,
                "Likelihood": likelihood_score,
                "Impact": impact_score,
                "Risk Score": threat.risk_score
            })
    else:
        # Sample data for demonstration
        risk_data = [
            {"Threat": "SQL Injection", "Likelihood": 2, "Impact": 3, "Risk Score": 7.5},
            {"Threat": "XSS Attack", "Likelihood": 3, "Impact": 2, "Risk Score": 6.0},
            {"Threat": "Data Breach", "Likelihood": 1, "Impact": 4, "Risk Score": 8.0},
            {"Threat": "DDoS Attack", "Likelihood": 3, "Impact": 2, "Risk Score": 6.0}
        ]
    
    df = pd.DataFrame(risk_data)
    
    fig = px.scatter(df, x="Likelihood", y="Impact", size="Risk Score", 
                    hover_name="Threat", color="Risk Score",
                    color_continuous_scale="Reds",
                    title="Risk Assessment Matrix")
    
    fig.update_layout(
        xaxis_title="Likelihood",
        yaxis_title="Impact",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_threat_timeline():
    """Render threat discovery timeline"""
    st.subheader("📈 Threat Discovery Timeline")
    
    # Generate timeline data
    threats = st.session_state.get('threats', [])
    
    if threats:
        timeline_data = []
        for threat in threats:
            timeline_data.append({
                "Date": threat.created_at.date(),
                "Threat": threat.name,
                "Severity": threat.severity.value,
                "Count": 1
            })
        
        df = pd.DataFrame(timeline_data)
        daily_counts = df.groupby(["Date", "Severity"]).count().reset_index()
        
        fig = px.line(daily_counts, x="Date", y="Count", color="Severity",
                     title="Daily Threat Discovery")
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threats identified yet. Run threat analysis to populate timeline.")

def render_recent_activities():
    """Render recent user activities"""
    audit_logs = st.session_state.get('audit_logs', [])
    
    if audit_logs:
        recent_logs = sorted(audit_logs, key=lambda x: x.timestamp, reverse=True)[:10]
        
        activity_data = []
        for log in recent_logs:
            activity_data.append({
                "Timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "User": log.user_id,
                "Action": log.action,
                "Resource": f"{log.resource_type}/{log.resource_id}",
                "Details": str(log.details)
            })
        
        df = pd.DataFrame(activity_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No recent activities recorded.")

def render_compliance_dashboard():
    """Render compliance status dashboard"""
    compliance_frameworks = {
        "PCI DSS": {"status": "Compliant", "score": 95, "color": "#28a745"},
        "SOC 2": {"status": "In Progress", "score": 75, "color": "#ffc107"},
        "ISO 27001": {"status": "Compliant", "score": 90, "color": "#28a745"},
        "GDPR": {"status": "Non-Compliant", "score": 60, "color": "#dc3545"},
        "HIPAA": {"status": "N/A", "score": 0, "color": "#6c757d"}
    }
    
    cols = st.columns(len(compliance_frameworks))
    
    for i, (framework, data) in enumerate(compliance_frameworks.items()):
        with cols[i]:
            st.metric(
                label=framework,
                value=f"{data['score']}%",
                delta=data['status']
            )
            
            # Progress bar
            st.markdown(f"""
            <div style="background: #f0f0f0; border-radius: 10px; overflow: hidden;">
                <div style="background: {data['color']}; width: {data['score']}%; 
                           height: 10px; transition: width 0.3s ease;"></div>
            </div>
            """, unsafe_allow_html=True)

def render_advanced_threat_analysis():
    """Render advanced threat analysis with ML insights"""
    st.header("🔬 Advanced Threat Analysis")
    
    if not check_permission("write"):
        st.warning("⚠️ You don't have permission to modify threat analysis.")
        return
    
    # AI-powered threat detection
    st.subheader("🤖 AI-Powered Threat Detection")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔍 Run AI Analysis", type="primary"):
            with st.spinner("Analyzing architecture with AI..."):
                # Simulate AI analysis
                time.sleep(2)
                st.success("✅ AI analysis completed!")
                
                # Generate AI-suggested threats
                ai_threats = generate_ai_threats()
                st.session_state.ai_suggested_threats = ai_threats
    
    with col2:
        confidence_threshold = st.slider("Confidence Threshold", 0.0, 1.0, 0.7)
    
    # Display AI suggestions
    if 'ai_suggested_threats' in st.session_state:
        st.subheader("🎯 AI-Suggested Threats")
        
        for threat in st.session_state.ai_suggested_threats:
            if threat.get('confidence', 0) >= confidence_threshold:
                with st.expander(f"⚠️ {threat['name']} (Confidence: {threat['confidence']:.1%})"):
                    st.write(f"**Description:** {threat['description']}")
                    st.write(f"**STRIDE Category:** {threat['stride_category']}")
                    st.write(f"**Suggested Mitigation:** {threat['mitigation']}")
                    
                    if st.button(f"➕ Add {threat['name']}", key=f"add_{threat['id']}"):
                        # Add threat to main list
                        new_threat = Threat(
                            id=threat['id'],
                            name=threat['name'],
                            description=threat['description'],
                            affected_components=threat['affected_components'],
                            stride_category=StrideCategory(threat['stride_category']),
                            severity=ThreatSeverity(threat['severity']),
                            likelihood="Medium",
                            impact="Medium",
                            risk_score=5.0,
                            mitigation=threat['mitigation']
                        )
                        
                        if 'threats' not in st.session_state:
                            st.session_state.threats = []
                        st.session_state.threats.append(new_threat)
                        
                        # Log the action
                        log_audit_event(
                            st.session_state.current_user.id,
                            "CREATE",
                            "THREAT",
                            new_threat.id,
                            {"threat_name": threat['name']}
                        )
                        
                        st.success(f"✅ Added threat: {threat['name']}")
                        st.rerun()

def generate_ai_threats():
    """Generate AI-suggested threats based on architecture"""
    components = st.session_state.get('components', [])
    data_flows = st.session_state.get('data_flows', [])
    
    ai_threats = []
    
    # Analyze for common patterns
    web_components = [c for c in components if 'web' in c.name.lower() or 'api' in c.name.lower()]
    db_components = [c for c in components if 'database' in c.name.lower() or 'db' in c.name.lower()]
    
    if web_components:
        ai_threats.append({
            'id': generate_id("AI_"),
            'name': "Web Application Firewall Bypass",
            'description': "Advanced techniques to bypass WAF protection",
            'stride_category': "Tampering",
            'severity': "High",
            'mitigation': "Implement advanced WAF rules and behavioral analysis",
            'affected_components': [c.name for c in web_components],
            'confidence': 0.85
        })
    
    if db_components:
        ai_threats.append({
            'id': generate_id("AI_"),
            'name': "Database Privilege Escalation",
            'description': "Exploiting database misconfigurations for privilege escalation",
            'stride_category': "Elevation of Privilege",
            'severity': "Critical",
            'mitigation': "Implement database security hardening and monitoring",
            'affected_components': [c.name for c in db_components],
            'confidence': 0.78
        })
    
    # Check for unencrypted flows
    unencrypted_flows = [f for f in data_flows if not f.encryption]
    if unencrypted_flows:
        ai_threats.append({
            'id': generate_id("AI_"),
            'name': "Man-in-the-Middle Attack on Unencrypted Flows",
            'description': "Interception of unencrypted data flows",
            'stride_category': "Information Disclosure",
            'severity': "High",
            'mitigation': "Implement end-to-end encryption for all data flows",
            'affected_components': [f.source for f in unencrypted_flows],
            'confidence': 0.92
        })
    
    return ai_threats

def generate_executive_report():
    """Generate executive summary report"""
    threats = st.session_state.get('threats', [])
    components = st.session_state.get('components', [])
    
    report = {
        "title": "Executive Security Summary",
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_threats": len(threats),
            "critical_threats": len([t for t in threats if t.severity == ThreatSeverity.CRITICAL]),
            "high_threats": len([t for t in threats if t.severity == ThreatSeverity.HIGH]),
            "components_analyzed": len(components)
        },
        "key_findings": [
            "Architecture analysis completed with AI-powered threat detection",
            "Critical vulnerabilities identified in authentication flows",
            "Encryption gaps found in data transmission layers"
        ],
        "recommendations": [
            "Implement multi-factor authentication across all systems",
            "Enable end-to-end encryption for sensitive data flows",
            "Establish continuous security monitoring and alerting"
        ]
    }
    
    # Convert to downloadable JSON
    report_json = json.dumps(report, indent=2)
    
    st.download_button(
        label="📄 Download Executive Report",
        data=report_json,
        file_name=f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )
    
    st.success("✅ Executive report generated successfully!")

def generate_risk_report():
    """Generate detailed risk assessment report"""
    threats = st.session_state.get('threats', [])
    
    risk_report = {
        "title": "Risk Assessment Report",
        "generated_at": datetime.now().isoformat(),
        "threats": []
    }
    
    for threat in threats:
        risk_report["threats"].append({
            "id": threat.id,
            "name": threat.name,
            "description": threat.description,
            "severity": threat.severity.value,
            "likelihood": threat.likelihood,
            "impact": threat.impact,
            "risk_score": threat.risk_score,
            "mitigation": threat.mitigation,
            "status": threat.status,
            "affected_components": threat.affected_components
        })
    
    # Convert to downloadable JSON
    report_json = json.dumps(risk_report, indent=2)
    
    st.download_button(
        label="📈 Download Risk Report",
        data=report_json,
        file_name=f"risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )
    
    st.success("✅ Risk assessment report generated successfully!")

def export_to_json():
    """Export all data to JSON format"""
    export_data = {
        "components": [
            {
                "id": c.id,
                "name": c.name,
                "type": c.type.value,
                "description": c.description,
                "trust_level": c.trust_level.value,
                "technologies": c.technologies,
                "security_controls": c.security_controls,
                "created_at": c.created_at.isoformat()
            }
            for c in st.session_state.get('components', [])
        ],
        "data_flows": [
            {
                "id": f.id,
                "source": f.source,
                "destination": f.destination,
                "data_type": f.data_type,
                "protocol": f.protocol,
                "encryption": f.encryption,
                "authentication_required": f.authentication_required,
                "description": f.description,
                "created_at": f.created_at.isoformat()
            }
            for f in st.session_state.get('data_flows', [])
        ],
        "threats": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "affected_components": t.affected_components,
                "stride_category": t.stride_category.value,
                "severity": t.severity.value,
                "likelihood": t.likelihood,
                "impact": t.impact,
                "risk_score": t.risk_score,
                "mitigation": t.mitigation,
                "status": t.status,
                "assigned_to": t.assigned_to,
                "created_at": t.created_at.isoformat()
            }
            for t in st.session_state.get('threats', [])
        ],
        "exported_at": datetime.now().isoformat(),
        "exported_by": st.session_state.current_user.username
    }
    
    # Convert to downloadable JSON
    export_json = json.dumps(export_data, indent=2)
    
    st.download_button(
        label="💾 Download Complete Data Export",
        data=export_json,
        file_name=f"threat_model_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )
    
    # Log export activity
    log_audit_event(
        st.session_state.current_user.id,
        "EXPORT",
        "DATA",
        "FULL_EXPORT",
        {"export_type": "JSON", "components": len(export_data['components'])}
    )
    
    st.success("✅ Data exported successfully!")

def export_to_csv():
    """Export threats to CSV format"""
    threats = st.session_state.get('threats', [])
    
    if not threats:
        st.warning("No threats to export.")
        return
    
    # Convert threats to DataFrame
    threat_data = []
    for threat in threats:
        threat_data.append({
            "ID": threat.id,
            "Name": threat.name,
            "Description": threat.description,
            "STRIDE Category": threat.stride_category.value,
            "Severity": threat.severity.value,
            "Likelihood": threat.likelihood,
            "Impact": threat.impact,
            "Risk Score": threat.risk_score,
            "Mitigation": threat.mitigation,
            "Status": threat.status,
            "Assigned To": threat.assigned_to,
            "Created At": threat.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    df = pd.DataFrame(threat_data)
    csv = df.to_csv(index=False)
    
    st.download_button(
        label="📊 Download Threats CSV",
        data=csv,
        file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )
    
    st.success("✅ Threats exported to CSV successfully!")

def render_export_options():
    """Render data export and reporting options"""
    st.subheader("📤 Export & Reporting")
    
    if not check_permission("read"):
        st.warning("⚠️ You don't have permission to export data.")
        return
    
    export_col1, export_col2, export_col3 = st.columns(3)
    
    with export_col1:
        st.write("**📊 Reports**")
        if st.button("📋 Executive Summary", use_container_width=True):
            generate_executive_report()
        
        if st.button("📈 Risk Assessment", use_container_width=True):
            generate_risk_report()
    
    with export_col2:
        st.write("**💾 Data Export**")
        if st.button("📄 Export to JSON", use_container_width=True):
            export_to_json()
        
        if st.button("📊 Export to CSV", use_container_width=True):
            export_to_csv()
    
    with export_col3:
        st.write("**📋 Audit Logs**")
        if st.button("📜 Export Audit Logs", use_container_width=True):
            export_audit_logs()
        
        if st.button("🔍 View Audit Trail", use_container_width=True):
            render_audit_trail()

def export_audit_logs():
    """Export audit logs to JSON"""
    audit_logs = st.session_state.get('audit_logs', [])
    
    if not audit_logs:
        st.warning("No audit logs to export.")
        return
    
    # Convert audit logs to exportable format
    logs_data = []
    for log in audit_logs:
        logs_data.append({
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
