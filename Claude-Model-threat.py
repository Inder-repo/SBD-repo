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
    TRUST_BOUNDARY = "Trust Boundary" # Although not used for component creation, useful for type checking

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
    source: str # Name of source component
    target: str # Name of target component
    data_type: str
    protocol: str
    description: str
    port: Optional[int] = None
    encryption: bool = False
    authentication_required: bool = False
    data_classification: str = "Internal"
    crosses_trust_boundary: bool = False
    trust_boundary_crossed: Optional[str] = None # e.g., "Internet -> DMZ"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class TrustBoundary:
    id: str
    name: str
    components: List[str] # List of component names within this boundary
    security_level: SecurityLevel
    description: str
    color: str = "#4CAF50"
    boundary_type: str = "Network"  # Network, Process, Physical, Administrative
    controls: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class Threat:
    id: str
    name: str
    description: str
    affected_components: List[str] # List of component names affected
    affected_data_flows: List[str] = field(default_factory=list) # List of data flow IDs affected
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

# Enhanced Threat Patterns with Trust Boundary and Data Flow considerations
# These patterns are simplified and would be more extensive in a real enterprise app
ENHANCED_THREAT_PATTERNS = {
    "Component_Web_Application": [
        Threat(
            id="WEB001", name="SQL Injection",
            description="Malicious SQL code injection through user inputs affecting database integrity.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.TAMPERING,
            severity=ThreatSeverity.HIGH, mitigation="Implement parameterized queries, input validation, and stored procedures.",
            likelihood="Medium", impact="High", risk_score=0.0
        ),
        Threat(
            id="WEB002", name="Cross-Site Scripting (XSS)",
            description="Malicious scripts executed in user browsers compromising client-side security.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.TAMPERING,
            severity=ThreatSeverity.MEDIUM, mitigation="Implement output encoding, CSP headers, and input sanitization.",
            likelihood="High", impact="Medium", risk_score=0.0
        ),
        Threat(
            id="WEB003", name="Authentication Bypass",
            description="Unauthorized access to protected resources through authentication flaws.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.SPOOFING,
            severity=ThreatSeverity.HIGH, mitigation="Implement MFA, session management, and strong password policies.",
            likelihood="Low", impact="High", risk_score=0.0
        )
    ],
    "DataFlow_Insecure_Sensitive": [
        Threat(
            id="DF001", name="Data Eavesdropping (Insecure Transit)",
            description="Sensitive data transmitted over unencrypted or weak protocols, allowing interception.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            severity=ThreatSeverity.CRITICAL, mitigation="Enforce strong encryption (TLS 1.2+) for all sensitive data in transit.",
            likelihood="High", impact="Critical", risk_score=0.0
        ),
        Threat(
            id="DF002", name="Data Tampering (Insecure Transit)",
            description="Data integrity compromised due to lack of protection during transmission.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.TAMPERING,
            severity=ThreatSeverity.HIGH, mitigation="Implement message authentication codes (MACs) or digital signatures.",
            likelihood="Medium", impact="High", risk_score=0.0
        )
    ],
    "TrustBoundary_Crossing_Privilege_Escalation": [
        Threat(
            id="TB001", name="Trust Boundary Violation (Privilege Escalation)",
            description="Unauthorized privilege escalation when data or control flows cross trust boundaries without proper validation or least privilege.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            severity=ThreatSeverity.CRITICAL, mitigation="Implement strict input validation, output encoding, and enforce least privilege at boundary crossings.",
            likelihood="Medium", impact="Critical", risk_score=0.0
        )
    ],
    "TrustBoundary_Crossing_Info_Disclosure": [
        Threat(
            id="TB002", name="Trust Boundary Violation (Information Disclosure)",
            description="Sensitive information leakage across trust boundaries due to insufficient filtering or controls.",
            affected_components=[], affected_data_flows=[], stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            severity=ThreatSeverity.HIGH, mitigation="Implement data loss prevention (DLP), strict data filtering, and access controls at boundary crossings.",
            likelihood="Medium", impact="High", risk_score=0.0
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

    if 'user_name' not in st.session_state:
        st.session_state.user_name = "John Doe" # Added for display in header

def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix"""
    return f"{prefix}{str(uuid.uuid4())[:8]}"

def calculate_risk_score(likelihood: str, impact: str) -> float:
    """Calculate risk score based on likelihood and impact"""
    likelihood_map = {"Low": 1, "Medium": 2, "High": 3}
    impact_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    
    l_score = likelihood_map.get(likelihood, 2)
    i_score = impact_map.get(impact, 2)
    
    return (l_score * i_score) * 1.25  # Scale to 0-15 (max 3*4*1.25 = 15)

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

def analyze_trust_boundary_crossings(components: List[Component],
                                     data_flows: List[DataFlow],
                                     trust_boundaries: List[TrustBoundary]) -> List[DataFlow]:
    """Analyze which data flows cross trust boundaries and update them."""
    
    # Create a quick lookup for component to boundary mapping
    comp_to_boundary_map = {}
    for boundary in trust_boundaries:
        for comp_name in boundary.components:
            comp_to_boundary_map[comp_name] = boundary.id

    updated_flows = []
    for flow in data_flows:
        source_boundary_id = comp_to_boundary_map.get(flow.source)
        target_boundary_id = comp_to_boundary_map.get(flow.target)

        if source_boundary_id and target_boundary_id and source_boundary_id != target_boundary_id:
            flow.crosses_trust_boundary = True
            source_boundary_name = next((b.name for b in trust_boundaries if b.id == source_boundary_id), "Unknown")
            target_boundary_name = next((b.name for b in trust_boundaries if b.id == target_boundary_id), "Unknown")
            flow.trust_boundary_crossed = f"{source_boundary_name} → {target_boundary_name}"
        else:
            flow.crosses_trust_boundary = False
            flow.trust_boundary_crossed = None
        
        updated_flows.append(flow)
    
    return updated_flows

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
            label="🏗️ **Components**",
            value=len(st.session_state.get('components', [])),
            delta=f"+{len([c for c in st.session_state.get('components', []) if c.created_at.date() == datetime.now().date()])}"
        )
    
    with col2:
        st.metric(
            label="🔄 **Data Flows**",
            value=len(st.session_state.get('data_flows', [])),
            delta=f"+{len([f for f in st.session_state.get('data_flows', []) if f.created_at.date() == datetime.now().date()])}"
        )
    
    with col3:
        threats = st.session_state.get('threats', [])
        high_critical = len([t for t in threats if t.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]])
        st.metric(
            label="⚠️ **Critical/High Threats**",
            value=high_critical,
            delta=f"{high_critical}/{len(threats)}" if threats else "0/0"
        )
    
    with col4:
        boundaries = st.session_state.get('trust_boundaries', [])
        st.metric(
            label="🔐 **Trust Boundaries**",
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
            comp_name = st.text_input("Component Name*", placeholder="e.g., Web Application Server", key="comp_name_input")
            comp_type = st.selectbox("Component Type*", [t.value for t in ComponentType if t != ComponentType.TRUST_BOUNDARY], key="comp_type_select")
            comp_description = st.text_area("Description", placeholder="Detailed description of the component's purpose and function", key="comp_desc_input")
            
        with col2:
            comp_owner = st.text_input("Owner", placeholder="Team or individual responsible", key="comp_owner_input")
            comp_security_level = st.selectbox("Security Level", [s.value for s in SecurityLevel], key="comp_sec_level_select")
            comp_data_classification = st.selectbox("Data Classification",
                                                    ["Public", "Internal", "Confidential", "Restricted"], key="comp_data_class_select")
            
        # Position controls - now more prominent for diagram layout
        st.subheader("Position on Diagram (1-10 Grid)")
        pos_col1, pos_col2 = st.columns(2)
        with pos_col1:
            comp_x = st.slider("X Position", 1, 10, 5, key="comp_x_slider")
        with pos_col2:
            comp_y = st.slider("Y Position", 1, 10, 5, key="comp_y_slider")
            
        # Technologies
        comp_technologies = st.multiselect(
            "Technologies/Frameworks",
            ["Java", "Python", "Node.js", "React", "Angular", "PostgreSQL", "MongoDB",
             "Redis", "Docker", "Kubernetes", "AWS", "Azure", "GCP", "Nginx", "Apache"],
            help="Select applicable technologies", key="comp_tech_multiselect"
        )
        
        submitted = st.form_submit_button("➕ Add Component", type="primary")
        
        if submitted and comp_name and comp_type:
            # Check for duplicate component names
            if any(c.name == comp_name for c in st.session_state.components):
                st.error(f"❌ Component with name '{comp_name}' already exists. Please choose a unique name.")
                return

            new_component = Component(
                id=generate_id("COMP_"),
                name=comp_name,
                type=ComponentType(comp_type),
                description=comp_description,
                x=float(comp_x), # Ensure float for plotly
                y=float(comp_y), # Ensure float for plotly
                security_level=SecurityLevel(comp_security_level),
                technologies=comp_technologies,
                data_classification=comp_data_classification,
                owner=comp_owner or "Unknown"
            )
            
            st.session_state.components.append(new_component)
            # Re-analyze data flows if components are added/removed as their boundary context might change
            st.session_state.data_flows = analyze_trust_boundary_crossings(
                st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
            )
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
            source = st.selectbox("Source Component*", component_names, key="flow_source_select")
            target = st.selectbox("Target Component*", component_names, key="flow_target_select")
            data_type = st.text_input("Data Type*", placeholder="e.g., User Credentials, Payment Data", key="flow_data_type_input")
            
        with col2:
            protocol = st.selectbox("Protocol*", ["HTTPS", "HTTP", "TLS", "TCP", "UDP", "WebSocket", "gRPC", "SFTP", "SSH"], key="flow_protocol_select")
            port = st.number_input("Port", min_value=1, max_value=65535, value=443, key="flow_port_input")
            data_classification = st.selectbox("Data Classification",
                                              ["Public", "Internal", "Confidential", "Restricted"], key="flow_data_class_select")
        
        # Security controls
        st.subheader("Security Controls")
        sec_col1, sec_col2 = st.columns(2)
        with sec_col1:
            encryption = st.checkbox("Encrypted in Transit", value=True, key="flow_encryption_checkbox")
        with sec_col2:
            authentication = st.checkbox("Authentication Required", value=True, key="flow_auth_checkbox")
            
        flow_description = st.text_area("Description",
                                         placeholder="Describe the data flow and its business purpose", key="flow_desc_input")
        
        submitted = st.form_submit_button("➕ Add Data Flow", type="primary")
        
        if submitted and source and target and data_type:
            if source == target:
                st.error("❌ Source and target cannot be the same component.")
                return
            
            # Check for duplicate flow (same source, target, data type, protocol)
            if any(f.source == source and f.target == target and f.data_type == data_type and f.protocol == protocol
                   for f in st.session_state.data_flows):
                st.error(f"❌ A similar data flow from '{source}' to '{target}' with data type '{data_type}' and protocol '{protocol}' already exists.")
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
            # Re-analyze boundary crossings after adding a new flow
            st.session_state.data_flows = analyze_trust_boundary_crossings(
                st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
            )
            st.success(f"✅ Data flow from '{source}' to '{target}' added successfully!")
            st.rerun()

def render_trust_boundary_form():
    """Render enhanced trust boundary creation form"""
    st.subheader("🔐 Manage Trust Boundaries")
    
    # Quick setup with default boundaries
    if not st.session_state.trust_boundaries:
        st.info("💡 Start with default trust boundaries or create custom ones.")
        if st.button("🚀 Setup Default Trust Boundaries", type="primary", key="setup_default_tb_button"):
            st.session_state.trust_boundaries = create_default_trust_boundaries()
            # Update data flows after boundaries are created/updated
            st.session_state.data_flows = analyze_trust_boundary_crossings(
                st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
            )
            st.success("✅ Default trust boundaries created!")
            st.rerun()
    
    # Custom boundary creation
    with st.expander("➕ Create Custom Trust Boundary"):
        with st.form("trust_boundary_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                boundary_name = st.text_input("Boundary Name*", placeholder="e.g., Application Tier", key="tb_name_input")
                boundary_type = st.selectbox("Boundary Type", ["Network", "Process", "Physical", "Administrative"], key="tb_type_select")
                security_level = st.selectbox("Security Level*", [s.value for s in SecurityLevel], key="tb_sec_level_select")
                
            with col2:
                color = st.color_picker("Boundary Color", "#4CAF50", key="tb_color_picker")
                boundary_description = st.text_area("Description",
                                                     placeholder="Describe the trust boundary and its purpose", key="tb_desc_input")
            
            # Component selection
            if st.session_state.components:
                component_names = [c.name for c in st.session_state.components]
                selected_components = st.multiselect("Components in Boundary", component_names, key="tb_components_multiselect")
            else:
                selected_components = []
                st.info("Add components first to assign them to boundaries.")
            
            # Security controls
            available_controls = [
                "Firewall", "IDS/IPS", "DLP", "WAF", "Load Balancer", "VPN", "MFA",
                "Encryption", "Access Control", "Monitoring", "Audit Logging", "Network Segmentation",
                "Input Validation", "Output Encoding", "Parameterized Queries", "Secure Session Management"
            ]
            controls = st.multiselect("Security Controls", available_controls, key="tb_controls_multiselect")
            
            # Compliance requirements
            compliance_options = [
                "PCI DSS", "HIPAA", "SOC 2", "ISO 27001", "GDPR", "CCPA", "SOX", "FISMA", "NIST CSF"
            ]
            compliance = st.multiselect("Compliance Requirements", compliance_options, key="tb_compliance_multiselect")
            
            submitted = st.form_submit_button("➕ Create Trust Boundary", type="primary")
            
            if submitted and boundary_name and security_level:
                # Check for duplicate boundary names
                if any(b.name == boundary_name for b in st.session_state.trust_boundaries):
                    st.error(f"❌ Trust Boundary with name '{boundary_name}' already exists. Please choose a unique name.")
                    return

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
                # Update data flows after boundaries are created/updated
                st.session_state.data_flows = analyze_trust_boundary_crossings(
                    st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
                )
                st.success(f"✅ Trust boundary '{boundary_name}' created successfully!")
                st.rerun()

    # Display and edit existing trust boundaries
    st.subheader("Existing Trust Boundaries")
    if not st.session_state.trust_boundaries:
        st.info("No custom trust boundaries defined yet.")
    else:
        for i, boundary in enumerate(st.session_state.trust_boundaries):
            with st.expander(f"⚙️ {boundary.name} (ID: {boundary.id})"):
                with st.form(f"edit_boundary_form_{boundary.id}"):
                    edited_name = st.text_input("Boundary Name", boundary.name, key=f"name_{boundary.id}")
                    edited_type = st.selectbox("Boundary Type", ["Network", "Process", "Physical", "Administrative"], index=["Network", "Process", "Physical", "Administrative"].index(boundary.boundary_type), key=f"type_{boundary.id}")
                    edited_security_level = st.selectbox("Security Level", [s.value for s in SecurityLevel], index=[s.value for s in SecurityLevel].index(boundary.security_level.value), key=f"sec_level_{boundary.id}")
                    edited_color = st.color_picker("Boundary Color", boundary.color, key=f"color_{boundary.id}")
                    edited_description = st.text_area("Description", boundary.description, key=f"desc_{boundary.id}")

                    # Components can be updated here
                    current_component_names = [c.name for c in st.session_state.components]
                    selected_comps_for_boundary = st.multiselect(
                        "Components in Boundary",
                        current_component_names,
                        default=[c for c in boundary.components if c in current_component_names], # Only show existing components
                        key=f"comps_{boundary.id}"
                    )

                    edited_controls = st.multiselect("Security Controls", available_controls, default=boundary.controls, key=f"controls_{boundary.id}")
                    edited_compliance = st.multiselect("Compliance Requirements", compliance_options, default=boundary.compliance_requirements, key=f"compliance_{boundary.id}")

                    update_button = st.form_submit_button("💾 Update Boundary", type="secondary")
                    delete_button = st.form_submit_button("🗑️ Delete Boundary", help="This will permanently delete the boundary.", on_click=lambda b_id=boundary.id: delete_trust_boundary(b_id), key=f"delete_{boundary.id}")

                    if update_button:
                        # Check for duplicate name if name changed
                        if edited_name != boundary.name and any(b.name == edited_name for b in st.session_state.trust_boundaries if b.id != boundary.id):
                            st.error(f"❌ Trust Boundary with name '{edited_name}' already exists. Please choose a unique name.")
                            st.rerun() # Rerun to show error and keep form state
                            return

                        # Update references in components and data flows if name changed
                        if edited_name != boundary.name:
                            for comp in st.session_state.components:
                                if comp.name in boundary.components: # If component was in old boundary, it's now in new name
                                    pass # Component name doesn't change, only the boundary's name
                            for flow in st.session_state.data_flows:
                                if flow.trust_boundary_crossed and boundary.name in flow.trust_boundary_crossed:
                                    flow.trust_boundary_crossed = flow.trust_boundary_crossed.replace(boundary.name, edited_name)

                        boundary.name = edited_name
                        boundary.boundary_type = edited_type
                        boundary.security_level = SecurityLevel(edited_security_level)
                        boundary.color = edited_color
                        boundary.description = edited_description
                        boundary.components = selected_comps_for_boundary
                        boundary.controls = edited_controls
                        boundary.compliance_requirements = edited_compliance
                        boundary.updated_at = datetime.now()
                        st.session_state.data_flows = analyze_trust_boundary_crossings(
                            st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
                        ) # Re-analyze after updates
                        st.success(f"✅ Trust boundary '{boundary.name}' updated successfully!")
                        st.rerun()

def delete_trust_boundary(boundary_id: str):
    """Deletes a trust boundary from the session state."""
    st.session_state.trust_boundaries = [b for b in st.session_state.trust_boundaries if b.id != boundary_id]
    # Re-analyze data flows as boundary information might have changed
    st.session_state.data_flows = analyze_trust_boundary_crossings(
        st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
    )
    st.success("Trust boundary deleted successfully!")
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
            "ID": comp.id, # Added ID for potential reference
            "Name": comp.name,
            "Type": comp.type.value,
            "Security Level": comp.security_level.value,
            "Data Classification": comp.data_classification,
            "Owner": comp.owner,
            "Technologies": ", ".join(comp.technologies) if comp.technologies else "None",
            "X": comp.x,
            "Y": comp.y,
            "Created": comp.created_at.strftime("%Y-%m-%d"),
            "Last Updated": comp.updated_at.strftime("%Y-%m-%d %H:%M")
        })
    
    df = pd.DataFrame(component_data)
    
    # Add filters
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    
    with filter_col1:
        type_filter = st.selectbox("Filter by Type", ["All"] + [t.value for t in ComponentType if t != ComponentType.TRUST_BOUNDARY], key="comp_type_filter_table")
    
    with filter_col2:
        security_filter = st.selectbox("Filter by Security Level", ["All"] + [s.value for s in SecurityLevel], key="comp_sec_filter_table")
    
    with filter_col3:
        classification_filter = st.selectbox("Filter by Data Classification",
                                            ["All", "Public", "Internal", "Confidential", "Restricted"], key="comp_data_filter_table")
    
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
    st.markdown("---")
    st.subheader("Component Management Actions")
    col_del, col_edit = st.columns(2)

    with col_del:
        comp_to_delete = st.selectbox(
            "Select Component to Delete",
            [""] + [c.name for c in st.session_state.components],
            key="delete_comp_select"
        )
        if st.button("🗑️ Delete Selected Component", type="secondary", disabled=comp_to_delete == ""):
            if comp_to_delete:
                delete_component(comp_to_delete)
    
    with col_edit:
        comp_to_edit_name = st.selectbox(
            "Select Component to Edit",
            [""] + [c.name for c in st.session_state.components],
            key="edit_comp_select"
        )
        if comp_to_edit_name:
            selected_comp = next((c for c in st.session_state.components if c.name == comp_to_edit_name), None)
            if selected_comp:
                with st.expander(f"Edit {selected_comp.name}"):
                    edit_component_form(selected_comp)

    st.markdown("---")
    if st.button("🚨 Clear All Components, Data Flows & Threats", type="secondary"):
        if st.session_state.components or st.session_state.data_flows or st.session_state.threats:
            if st.popover("Confirm Clear All"):
                if st.button("Yes, Clear All (Irreversible)", type="primary", key="confirm_clear_all"):
                    st.session_state.components = []
                    st.session_state.data_flows = []  # Clear dependent data flows
                    st.session_state.trust_boundaries = create_default_trust_boundaries() # Reset boundaries too
                    st.session_state.threats = [] # Clear threats
                    st.success("✅ All components, data flows, and threats cleared!")
                    st.rerun()

def delete_component(component_name: str):
    """Deletes a component and any associated data flows."""
    # Find the component ID
    comp_id = next((c.id for c in st.session_state.components if c.name == component_name), None)

    if comp_id:
        st.session_state.components = [c for c in st.session_state.components if c.name != component_name]
        # Remove data flows where this component is source or target
        st.session_state.data_flows = [
            f for f in st.session_state.data_flows
            if f.source != component_name and f.target != component_name
        ]
        # Remove component from any trust boundaries it was part of
        for boundary in st.session_state.trust_boundaries:
            if component_name in boundary.components:
                boundary.components.remove(component_name)
        # Remove threats associated with this component
        st.session_state.threats = [
            t for t in st.session_state.threats
            if component_name not in t.affected_components
        ]

        # Re-analyze data flows as boundary associations might have changed
        st.session_state.data_flows = analyze_trust_boundary_crossings(
            st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
        )
        st.success(f"✅ Component '{component_name}' and its associated data flows/threats deleted.")
        st.rerun()

def edit_component_form(component: Component):
    """Renders a form to edit an existing component."""
    with st.form(f"edit_comp_form_{component.id}"):
        edited_name = st.text_input("Component Name*", component.name, key=f"edit_name_{component.id}")
        edited_type = st.selectbox("Component Type*", [t.value for t in ComponentType if t != ComponentType.TRUST_BOUNDARY], index=[t.value for t in ComponentType if t != ComponentType.TRUST_BOUNDARY].index(component.type.value), key=f"edit_type_{component.id}")
        edited_description = st.text_area("Description", component.description, key=f"edit_desc_{component.id}")
        edited_owner = st.text_input("Owner", component.owner, key=f"edit_owner_{component.id}")
        edited_security_level = st.selectbox("Security Level", [s.value for s in SecurityLevel], index=[s.value for s in SecurityLevel].index(component.security_level.value), key=f"edit_sec_level_{component.id}")
        edited_data_classification = st.selectbox("Data Classification", ["Public", "Internal", "Confidential", "Restricted"], index=["Public", "Internal", "Confidential", "Restricted"].index(component.data_classification), key=f"edit_data_class_{component.id}")

        st.markdown("---")
        st.write("Position (adjust if needed)")
        edited_x = st.slider("X Position", 1, 10, int(component.x), key=f"edit_x_{component.id}")
        edited_y = st.slider("Y Position", 1, 10, int(component.y), key=f"edit_y_{component.id}")

        edited_technologies = st.multiselect(
            "Technologies/Frameworks",
            ["Java", "Python", "Node.js", "React", "Angular", "PostgreSQL", "MongoDB",
             "Redis", "Docker", "Kubernetes", "AWS", "Azure", "GCP", "Nginx", "Apache"],
            default=component.technologies,
            key=f"edit_tech_{component.id}"
        )

        update_submitted = st.form_submit_button("💾 Update Component", type="primary")

        if update_submitted:
            # Check for duplicate name if name changed
            if edited_name != component.name and any(c.name == edited_name for c in st.session_state.components if c.id != component.id):
                st.error(f"❌ Component with name '{edited_name}' already exists. Please choose a unique name.")
                st.rerun() # Rerun to show error and keep form state
                return

            original_name = component.name # Capture original name before update
            
            # Update component in session state
            component.name = edited_name
            component.type = ComponentType(edited_type)
            component.description = edited_description
            component.owner = edited_owner
            component.security_level = SecurityLevel(edited_security_level)
            component.data_classification = edited_data_classification
            component.x = float(edited_x)
            component.y = float(edited_y)
            component.technologies = edited_technologies
            component.updated_at = datetime.now()

            # If component name changed, update references in data flows and trust boundaries and threats
            if original_name != edited_name:
                for flow in st.session_state.data_flows:
                    if flow.source == original_name:
                        flow.source = edited_name
                    if flow.target == original_name:
                        flow.target = edited_name
                for boundary in st.session_state.trust_boundaries:
                    if original_name in boundary.components:
                        idx = boundary.components.index(original_name)
                        boundary.components[idx] = edited_name
                for threat in st.session_state.threats:
                    if original_name in threat.affected_components:
                        idx = threat.affected_components.index(original_name)
                        threat.affected_components[idx] = edited_name

            # Re-analyze data flows as component name or boundary associations might have changed
            st.session_state.data_flows = analyze_trust_boundary_crossings(
                st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
            )
            st.success(f"✅ Component '{edited_name}' updated successfully!")
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
        show_labels = st.checkbox("Show Component Labels", value=True, key="show_labels_checkbox")
    with control_col2:
        show_boundaries = st.checkbox("Show Trust Boundaries", value=True, key="show_boundaries_checkbox")
    with control_col3:
        show_flows = st.checkbox("Show Data Flows", value=True, key="show_flows_checkbox")
    
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
        if st.button("📥 Export as PNG", key="export_png_button"):
            st.info("Feature available in full version - Export diagram as PNG")
    with export_col2:
        if st.button("📄 Export as PDF", key="export_pdf_button"):
            st.info("Feature available in full version - Export diagram as PDF")

def create_enhanced_architecture_diagram(components, data_flows, trust_boundaries,
                                         show_labels=True, show_boundaries=True, show_flows=True):
    """Create an enhanced professional architecture diagram"""
    fig = go.Figure()
    
    # Enhanced color scheme for component types
    component_type_colors = {
        ComponentType.EXTERNAL_ENTITY: '#FF6B6B', # Reddish
        ComponentType.PROCESS: '#4ECDC4',        # Teal
        ComponentType.DATA_STORE: '#45B7D1'      # Sky Blue
    }
    
    # Add trust boundaries as enhanced shapes
    if show_boundaries and trust_boundaries:
        for i, boundary in enumerate(trust_boundaries):
            boundary_components = [c for c in components if c.name in boundary.components]
            if boundary_components:
                # Calculate bounding box for components within this boundary
                min_x = min(c.x for c in boundary_components) - 0.7
                max_x = max(c.x for c in boundary_components) + 0.7
                min_y = min(c.y for c in boundary_components) - 0.7
                max_y = max(c.y for c in boundary_components) + 0.7
                
                # Add boundary rectangle with enhanced styling
                fig.add_shape(
                    type="rect",
                    x0=min_x, y0=min_y,
                    x1=max_x, y1=max_y,
                    fillcolor=boundary.color,
                    opacity=0.15, # Slightly less opaque
                    line=dict(width=3, color=boundary.color, dash="dashdot"), # More distinct dash pattern
                    layer="below",
                    name=boundary.name, # Name for hover info
                    xref="x", yref="y"
                )
                
                # Add enhanced boundary label - positioned dynamically
                fig.add_annotation(
                    x=min_x + (max_x - min_x) / 2, # Center horizontally
                    y=max_y + 0.3, # Slightly above the top edge
                    text=f"<b>{boundary.name}</b><br>({boundary.security_level.value} Trust)",
                    showarrow=False,
                    font=dict(
                        family="Arial, sans-serif",
                        size=12,
                        color=boundary.color
                    ),
                    align="center",
                    bordercolor=boundary.color,
                    borderwidth=1,
                    borderpad=4,
                    bgcolor="rgba(255,255,255,0.8)",
                    opacity=0.9
                )

    # Add components as scatter points
    component_x = [c.x for c in components]
    component_y = [c.y for c in components]
    component_names = [c.name for c in components]

    # Create hover text
    hover_texts = []
    for comp in components:
        tech_list = ", ".join(comp.technologies) if comp.technologies else "None"
        hover_text = (
            f"<b>{comp.name}</b><br>"
            f"Type: {comp.type.value}<br>"
            f"Security Level: {comp.security_level.value}<br>"
            f"Data Classification: {comp.data_classification}<br>"
            f"Owner: {comp.owner}<br>"
            f"Technologies: {tech_list}<br>"
            f"Description: {comp.description}"
        )
        hover_texts.append(hover_text)

    # Use a list of colors based on component type
    marker_colors = [component_type_colors.get(c.type, '#6c757d') for c in components] # Default grey for unknown type

    fig.add_trace(go.Scatter(
        x=component_x,
        y=component_y,
        mode='markers' + ('+text' if show_labels else ''),
        text=component_names if show_labels else None,
        textposition="bottom center",
        marker=dict(
            size=30,
            symbol='circle', # Can be customized based on type if needed
            color=marker_colors,
            line=dict(width=2, color='DarkSlateGrey')
        ),
        # Use customdata for hovertemplate for richer info
        hovertemplate='%{customdata}<extra></extra>',
        customdata=hover_texts,
        name='Components'
    ))

    # Add data flows as arrows
    if show_flows and data_flows:
        for flow in data_flows:
            source_comp = next((c for c in components if c.name == flow.source), None)
            target_comp = next((c for c in components if c.name == flow.target), None)

            if source_comp and target_comp:
                line_color = 'grey'
                line_width = 1
                dash_style = 'solid'
                if flow.crosses_trust_boundary:
                    line_color = ENTERPRISE_THEME['warning_color'] # Highlight boundary crossings
                    line_width = 3
                    dash_style = 'dash'

                flow_hover_text = (
                    f"<b>Data Flow: {flow.source} → {flow.target}</b><br>"
                    f"Data Type: {flow.data_type}<br>"
                    f"Protocol: {flow.protocol}{f':{flow.port}' if flow.port else ''}<br>"
                    f"Encryption: {'Yes' if flow.encryption else 'No'}<br>"
                    f"Authentication: {'Required' if flow.authentication_required else 'Not Required'}<br>"
                    f"Crosses Trust Boundary: {'Yes' if flow.crosses_trust_boundary else 'No'}"
                    f"{f' ({flow.trust_boundary_crossed})' if flow.crosses_trust_boundary else ''}<br>"
                    f"Description: {flow.description}"
                )

                fig.add_annotation(
                    x=target_comp.x,
                    y=target_comp.y,
                    ax=source_comp.x,
                    ay=source_comp.y,
                    xref="x", yref="y", axref="x", ayref="y",
                    showarrow=True,
                    arrowhead=2, # Arrowhead style
                    arrowsize=1,
                    arrowwidth=line_width,
                    arrowcolor=line_color,
                    hovertext=flow_hover_text,
                    hoverlabel=dict(bgcolor="white", font_size=10, font_family="Arial"),
                    # Set the line style
                    line=dict(
                        color=line_color,
                        width=line_width,
                        dash=dash_style
                    )
                )

    fig.update_layout(
        title_text="System Architecture Diagram",
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            visible=False,
            range=[0, 11] # Adjust range based on expected component positions
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            visible=False,
            scaleanchor="x",
            scaleratio=1,
            range=[0, 11] # Adjust range
        ),
        hovermode="closest",
        showlegend=False,
        height=600,
        plot_bgcolor=ENTERPRISE_THEME['background_color'],
        paper_bgcolor=ENTERPRISE_THEME['background_color'],
        margin=dict(l=20, r=20, t=50, b=20)
    )

    return fig

# Part 3: Threat Modeling and Risk Management
def perform_threat_analysis(components: List[Component], data_flows: List[DataFlow], trust_boundaries: List[TrustBoundary]):
    """
    Performs a comprehensive threat analysis based on the current architecture.
    Populates st.session_state.threats with identified threats, risks, and mitigations.
    """
    st.session_state.threats = [] # Clear existing threats for fresh analysis
    new_threats_count = 0

    # Analyze Components for threats
    for comp in components:
        # Example: Web Application Component Threats
        if comp.type == ComponentType.PROCESS and ("Web Application" in comp.technologies or "Nginx" in comp.technologies or "Apache" in comp.technologies):
            for threat_template in ENHANCED_THREAT_PATTERNS["Component_Web_Application"]:
                if not any(t.name == threat_template.name and comp.name in t.affected_components for t in st.session_state.threats):
                    new_threat = Threat(
                        id=generate_id("THRT_"),
                        name=threat_template.name,
                        description=threat_template.description.replace("database", "the database connected to " + comp.name),
                        affected_components=[comp.name],
                        affected_data_flows=[],
                        stride_category=threat_template.stride_category,
                        severity=threat_template.severity,
                        mitigation=threat_template.mitigation,
                        likelihood=threat_template.likelihood,
                        impact=threat_template.impact,
                        risk_score=calculate_risk_score(threat_template.likelihood, threat_template.impact),
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    )
                    st.session_state.threats.append(new_threat)
                    new_threats_count += 1
        
        # Add more component-specific threat logic here (e.g., for Data Stores, External Entities)
        # Example: Data Store with sensitive data and no encryption
        if comp.type == ComponentType.DATA_STORE and comp.data_classification in ["Confidential", "Restricted"]:
            # This is a placeholder, real check would involve looking at controls
            if "Encryption" not in comp.technologies: # Simplified check
                threat_name = "Sensitive Data at Rest Exposure"
                if not any(t.name == threat_name and comp.name in t.affected_components for t in st.session_state.threats):
                    st.session_state.threats.append(Threat(
                        id=generate_id("THRT_"), name=threat_name,
                        description=f"Sensitive data in {comp.name} is not encrypted at rest.",
                        affected_components=[comp.name], affected_data_flows=[], stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                        severity=ThreatSeverity.CRITICAL, mitigation="Implement database encryption at rest (e.g., TDE, disk encryption).",
                        likelihood="Medium", impact="Critical", risk_score=calculate_risk_score("Medium", "Critical")
                    ))
                    new_threats_count += 1


    # Analyze Data Flows for threats
    for flow in data_flows:
        # Insecure Sensitive Data Flow
        if flow.data_classification in ["Confidential", "Restricted"] and not flow.encryption:
            for threat_template in ENHANCED_THREAT_PATTERNS["DataFlow_Insecure_Sensitive"]:
                # Check for existing threat affecting this specific flow
                if not any(t.name == threat_template.name and flow.id in t.affected_data_flows for t in st.session_state.threats):
                    new_threat = Threat(
                        id=generate_id("THRT_"),
                        name=threat_template.name,
                        description=threat_template.description.replace("Sensitive data", f"Sensitive data ({flow.data_type})"),
                        affected_components=[flow.source, flow.target], # Affects both ends of the flow
                        affected_data_flows=[flow.id],
                        stride_category=threat_template.stride_category,
                        severity=threat_template.severity,
                        mitigation=threat_template.mitigation,
                        likelihood=threat_template.likelihood,
                        impact=threat_template.impact,
                        risk_score=calculate_risk_score(threat_template.likelihood, threat_template.impact),
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    )
                    st.session_state.threats.append(new_threat)
                    new_threats_count += 1

        # Data Flow crossing Trust Boundary without Authentication
        if flow.crosses_trust_boundary and not flow.authentication_required:
            threat_name = "Unauthorized Access Across Trust Boundary"
            if not any(t.name == threat_name and flow.id in t.affected_data_flows for t in st.session_state.threats):
                st.session_state.threats.append(Threat(
                    id=generate_id("THRT_"), name=threat_name,
                    description=f"Data flow '{flow.data_type}' from {flow.source} to {flow.target} crosses trust boundary ({flow.trust_boundary_crossed}) without authentication.",
                    affected_components=[flow.source, flow.target], affected_data_flows=[flow.id],
                    stride_category=StrideCategory.SPOOFING, severity=ThreatSeverity.HIGH,
                    mitigation="Implement strong authentication mechanisms at trust boundary crossings (e.g., mutual TLS, API keys).",
                    likelihood="High", impact="High", risk_score=calculate_risk_score("High", "High")
                ))
                new_threats_count += 1

    # Analyze Trust Boundaries for threats (especially for flows crossing them)
    # This is partially covered by data flow analysis, but can add more general boundary threats
    for boundary in trust_boundaries:
        # Check for flows crossing into/out of this boundary
        flows_crossing_this_boundary = [
            f for f in data_flows if f.crosses_trust_boundary and boundary.name in f.trust_boundary_crossed
        ]

        if flows_crossing_this_boundary:
            # Example: Privilege Escalation Across Boundaries
            for threat_template in ENHANCED_THREAT_PATTERNS["TrustBoundary_Crossing_Privilege_Escalation"]:
                # Check if this specific threat (by name) is already added for this boundary context
                if not any(t.name == threat_template.name and boundary.name in t.description for t in st.session_state.threats):
                    st.session_state.threats.append(Threat(
                        id=generate_id("THRT_"), name=threat_template.name,
                        description=f"{threat_template.description} (Context: {boundary.name} boundary).",
                        affected_components=boundary.components, # Affects components within the boundary
                        affected_data_flows=[f.id for f in flows_crossing_this_boundary],
                        stride_category=threat_template.stride_category,
                        severity=threat_template.severity,
                        mitigation=threat_template.mitigation,
                        likelihood=threat_template.likelihood,
                        impact=threat_template.impact,
                        risk_score=calculate_risk_score(threat_template.likelihood, threat_template.impact),
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    ))
                    new_threats_count += 1
            
            # Example: Information Disclosure Across Boundaries
            for threat_template in ENHANCED_THREAT_PATTERNS["TrustBoundary_Crossing_Info_Disclosure"]:
                if not any(t.name == threat_template.name and boundary.name in t.description for t in st.session_state.threats):
                    st.session_state.threats.append(Threat(
                        id=generate_id("THRT_"), name=threat_template.name,
                        description=f"{threat_template.description} (Context: {boundary.name} boundary).",
                        affected_components=boundary.components,
                        affected_data_flows=[f.id for f in flows_crossing_this_boundary],
                        stride_category=threat_template.stride_category,
                        severity=threat_template.severity,
                        mitigation=threat_template.mitigation,
                        likelihood=threat_template.likelihood,
                        impact=threat_template.impact,
                        risk_score=calculate_risk_score(threat_template.likelihood, threat_template.impact),
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    ))
                    new_threats_count += 1

    if new_threats_count > 0:
        st.success(f"✅ Threat analysis complete! Identified {new_threats_count} new potential threats.")
    else:
        st.info("No new threats identified based on the current architecture and threat patterns.")

def render_threat_management():
    """Render threat identification and management section"""
    st.subheader("🚨 Threat Identification & Management")
    
    st.info("💡 Build your architecture in the 'Components', 'Data Flows', and 'Trust Boundaries' sections, then click 'Run Threat Analysis' to identify potential threats.")

    col_threat_actions = st.columns(2)
    with col_threat_actions[0]:
        if st.button("⚡ Run Threat Analysis", type="primary", key="run_threat_analysis_button"):
            perform_threat_analysis(st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries)
            st.rerun()
    with col_threat_actions[1]:
        if st.button("🗑️ Clear All Identified Threats", type="secondary", key="clear_all_threats_button"):
            if st.popover("Confirm Clear Threats"):
                if st.button("Yes, Clear Threats", key="confirm_clear_threats"):
                    st.session_state.threats = []
                    st.success("✅ All identified threats cleared.")
                    st.rerun()

    st.markdown("---")
    # Manual Threat Creation Form
    with st.expander("➕ Manually Add a Threat"):
        with st.form("add_threat_form", clear_on_submit=True):
            col_t1, col_t2 = st.columns(2)
            with col_t1:
                threat_name = st.text_input("Threat Name*", placeholder="e.g., Unauthorized Access", key="manual_threat_name")
                threat_description = st.text_area("Description", placeholder="Detailed explanation of the threat", key="manual_threat_desc")
                
                # Select affected components (using component names)
                affected_comps_options = [c.name for c in st.session_state.components]
                affected_comps = st.multiselect("Affected Components (Optional)", affected_comps_options, key="manual_threat_affected_comps")

                # Select affected data flows (using flow IDs/descriptions)
                affected_flows_options = [f"{f.source} -> {f.target} ({f.data_type})" for f in st.session_state.data_flows]
                affected_flows_ids = [f.id for f in st.session_state.data_flows]
                selected_flow_indices = st.multiselect(
                    "Affected Data Flows (Optional)",
                    options=list(range(len(affected_flows_options))),
                    format_func=lambda x: affected_flows_options[x],
                    key="manual_threat_affected_flows"
                )
                actual_affected_flow_ids = [affected_flows_ids[i] for i in selected_flow_indices]

                stride_cat = st.selectbox("STRIDE Category*", [s.value for s in StrideCategory], key="manual_threat_stride")
            with col_t2:
                severity = st.selectbox("Severity*", [s.value for s in ThreatSeverity], key="manual_threat_severity")
                likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"], key="manual_threat_likelihood")
                impact = st.selectbox("Impact", ["Low", "Medium", "High", "Critical"], key="manual_threat_impact")
                mitigation = st.text_area("Proposed Mitigation", placeholder="Steps to address this threat", key="manual_threat_mitigation")
                due_date_input = st.date_input("Due Date (Optional)", value=None, min_value=datetime.now().date(), key="manual_threat_due_date")
                assigned_to = st.text_input("Assigned To", value="Unassigned", key="manual_threat_assigned_to")

            submit_threat = st.form_submit_button("➕ Add Threat", type="primary")

            if submit_threat and threat_name and stride_cat and severity:
                if not affected_comps and not actual_affected_flow_ids:
                    st.error("❌ Please select at least one affected component or data flow for the threat.")
                    return

                calculated_risk_score = calculate_risk_score(likelihood, impact)
                new_threat = Threat(
                    id=generate_id("THRT_"),
                    name=threat_name,
                    description=threat_description,
                    affected_components=affected_comps,
                    affected_data_flows=actual_affected_flow_ids,
                    stride_category=StrideCategory(stride_cat),
                    severity=ThreatSeverity(severity),
                    mitigation=mitigation,
                    likelihood=likelihood,
                    impact=impact,
                    risk_score=calculated_risk_score,
                    status="Open",
                    assigned_to=assigned_to,
                    due_date=datetime.combine(due_date_input, datetime.min.time()) if due_date_input else None
                )
                st.session_state.threats.append(new_threat)
                st.success(f"✅ Threat '{threat_name}' added successfully!")
                st.rerun()
    
    st.markdown("---")
    # Threat Table and Management
    st.subheader("📊 Identified Threats")

    if not st.session_state.threats:
        st.info("No threats identified yet. Run analysis or add manually.")
        return

    threat_df_data = []
    for threat in st.session_state.threats:
        affected_flows_names = []
        for flow_id in threat.affected_data_flows:
            flow_obj = next((f for f in st.session_state.data_flows if f.id == flow_id), None)
            if flow_obj:
                affected_flows_names.append(f"{flow_obj.source} -> {flow_obj.target} ({flow_obj.data_type})")

        threat_df_data.append({
            "ID": threat.id,
            "Threat Name": threat.name,
            "Description": threat.description,
            "Affected Components": ", ".join(threat.affected_components) if threat.affected_components else "N/A",
            "Affected Data Flows": "; ".join(affected_flows_names) if affected_flows_names else "N/A",
            "STRIDE Category": threat.stride_category.value,
            "Severity": threat.severity.value,
            "Likelihood": threat.likelihood,
            "Impact": threat.impact,
            "Risk Score": f"{threat.risk_score:.1f}",
            "Mitigation": threat.mitigation,
            "Status": threat.status,
            "Assigned To": threat.assigned_to,
            "Due Date": threat.due_date.strftime("%Y-%m-%d") if threat.due_date else "N/A",
            "Last Updated": threat.updated_at.strftime("%Y-%m-%d %H:%M")
        })
    threat_df = pd.DataFrame(threat_df_data)

    # Filters for threats
    filter_t1, filter_t2, filter_t3, filter_t4 = st.columns(4)
    with filter_t1:
        severity_filter = st.selectbox("Filter by Severity", ["All"] + [s.value for s in ThreatSeverity], key="threat_sev_filter")
    with filter_t2:
        stride_filter = st.selectbox("Filter by STRIDE Category", ["All"] + [s.value for s in StrideCategory], key="threat_stride_filter")
    with filter_t3:
        status_filter = st.selectbox("Filter by Status", ["All", "Open", "Mitigated", "In Progress", "Closed"], key="threat_status_filter")
    with filter_t4:
        assignee_filter_options = ["All"] + sorted(list(set([t.assigned_to for t in st.session_state.threats if t.assigned_to != "Unassigned"]))) + ["Unassigned"]
        assigned_to_filter = st.selectbox("Filter by Assignee", assignee_filter_options, key="threat_assignee_filter")


    filtered_threat_df = threat_df.copy()
    if severity_filter != "All":
        filtered_threat_df = filtered_threat_df[filtered_threat_df["Severity"] == severity_filter]
    if stride_filter != "All":
        filtered_threat_df = filtered_threat_df[filtered_threat_df["STRIDE Category"] == stride_filter]
    if status_filter != "All":
        filtered_threat_df = filtered_threat_df[filtered_threat_df["Status"] == status_filter]
    if assigned_to_filter != "All":
        filtered_threat_df = filtered_threat_df[filtered_threat_df["Assigned To"] == assigned_to_filter]

    st.dataframe(filtered_threat_df, use_container_width=True, hide_index=True)

    # Threat Management Actions (Edit/Delete)
    st.markdown("---")
    st.subheader("Threat Management Actions")
    threat_action_col1, threat_action_col2 = st.columns(2)

    with threat_action_col1:
        threat_to_edit_id = st.selectbox(
            "Select Threat to Edit",
            [""] + [t.id for t in st.session_state.threats],
            format_func=lambda x: next((f"{t.name} (ID: {t.id})" for t in st.session_state.threats if t.id == x), x),
            key="edit_threat_select"
        )
        if threat_to_edit_id:
            selected_threat = next((t for t in st.session_state.threats if t.id == threat_to_edit_id), None)
            if selected_threat:
                with st.expander(f"Edit Threat: {selected_threat.name}"):
                    edit_threat_form(selected_threat)

    with threat_action_col2:
        threat_to_delete_id = st.selectbox(
            "Select Threat to Delete",
            [""] + [t.id for t in st.session_state.threats],
            format_func=lambda x: next((f"{t.name} (ID: {t.id})" for t in st.session_state.threats if t.id == x), x),
            key="delete_threat_select"
        )
        if st.button("🗑️ Delete Selected Threat", type="secondary", disabled=threat_to_delete_id == ""):
            if threat_to_delete_id:
                delete_threat(threat_to_delete_id)

    st.markdown("---")
    st.subheader("Risk Score Distribution")
    if st.session_state.threats:
        risk_scores = [t.risk_score for t in st.session_state.threats]
        fig_hist = px.histogram(pd.DataFrame({"Risk Score": risk_scores}), x="Risk Score", nbins=10,
                                title="Distribution of Risk Scores",
                                color_discrete_sequence=[ENTERPRISE_THEME['primary_color']])
        fig_hist.update_layout(xaxis_title="Risk Score (0-15)", yaxis_title="Number of Threats")
        st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.info("No threats to display risk score distribution.")

def edit_threat_form(threat: Threat):
    """Renders a form to edit an existing threat."""
    with st.form(f"edit_threat_form_{threat.id}"):
        edited_name = st.text_input("Threat Name*", threat.name, key=f"edit_t_name_{threat.id}")
        edited_description = st.text_area("Description", threat.description, key=f"edit_t_desc_{threat.id}")
        
        current_component_names = [c.name for c in st.session_state.components]
        edited_affected_components = st.multiselect("Affected Components*", current_component_names, default=threat.affected_components, key=f"edit_t_affected_comps_{threat.id}")
        
        # For data flows, we need to map IDs back to names for display
        current_flow_options = [f"{f.source} -> {f.target} ({f.data_type})" for f in st.session_state.data_flows]
        current_flow_ids = [f.id for f in st.session_state.data_flows]
        
        default_selected_flow_indices = [current_flow_ids.index(fid) for fid in threat.affected_data_flows if fid in current_flow_ids]

        edited_affected_flow_indices = st.multiselect(
            "Affected Data Flows",
            options=list(range(len(current_flow_options))),
            format_func=lambda x: current_flow_options[x],
            default=default_selected_flow_indices,
            key=f"edit_t_affected_flows_{threat.id}"
        )
        edited_affected_data_flows_ids = [current_flow_ids[i] for i in edited_affected_flow_indices]

        edited_stride_cat = st.selectbox("STRIDE Category*", [s.value for s in StrideCategory], index=[s.value for s in StrideCategory].index(threat.stride_category.value), key=f"edit_t_stride_{threat.id}")
        edited_severity = st.selectbox("Severity*", [s.value for s in ThreatSeverity], index=[s.value for s in ThreatSeverity].index(threat.severity.value), key=f"edit_t_severity_{threat.id}")
        edited_likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(threat.likelihood), key=f"edit_t_likelihood_{threat.id}")
        edited_impact = st.selectbox("Impact", ["Low", "Medium", "High", "Critical"], index=["Low", "Medium", "High", "Critical"].index(threat.impact), key=f"edit_t_impact_{threat.id}")
        edited_mitigation = st.text_area("Proposed Mitigation", threat.mitigation, key=f"edit_t_mitigation_{threat.id}")
        edited_status = st.selectbox("Status", ["Open", "Mitigated", "In Progress", "Closed"], index=["Open", "Mitigated", "In Progress", "Closed"].index(threat.status), key=f"edit_t_status_{threat.id}")
        edited_assigned_to = st.text_input("Assigned To", threat.assigned_to, key=f"edit_t_assigned_to_{threat.id}")
        
        default_due_date = threat.due_date.date() if threat.due_date else None
        edited_due_date = st.date_input("Due Date (Optional)", value=default_due_date, min_value=datetime.now().date(), key=f"edit_t_due_date_{threat.id}")

        update_submitted = st.form_submit_button("💾 Update Threat", type="primary")

        if update_submitted:
            threat.name = edited_name
            threat.description = edited_description
            threat.affected_components = edited_affected_components
            threat.affected_data_flows = edited_affected_data_flows_ids
            threat.stride_category = StrideCategory(edited_stride_cat)
            threat.severity = ThreatSeverity(edited_severity)
            threat.likelihood = edited_likelihood
            threat.impact = edited_impact
            threat.risk_score = calculate_risk_score(edited_likelihood, edited_impact)
            threat.mitigation = edited_mitigation
            threat.status = edited_status
            threat.assigned_to = edited_assigned_to
            threat.due_date = datetime.combine(edited_due_date, datetime.min.time()) if edited_due_date else None
            threat.updated_at = datetime.now()
            st.success(f"✅ Threat '{edited_name}' updated successfully!")
            st.rerun()

def delete_threat(threat_id: str):
    """Deletes a threat from the session state."""
    st.session_state.threats = [t for t in st.session_state.threats if t.id != threat_id]
    st.success("Threat deleted successfully!")
    st.rerun()


# Part 4: Data Persistence and Export/Import

def object_to_dict(obj):
    """Recursively converts dataclass objects and Enums to dictionaries and their values."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, list):
        return [object_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {key: object_to_dict(value) for key, value in obj.items()}
    if hasattr(obj, '__dataclass_fields__'):
        return {field.name: object_to_dict(getattr(obj, field.name)) for field in obj.__dataclass_fields__.values()}
    return obj

def dict_to_object(data, cls):
    """Converts a dictionary back to a dataclass object, handling Enums and datetimes."""
    if data is None:
        return None
    if cls == datetime:
        return datetime.fromisoformat(data)
    if issubclass(cls, Enum):
        return cls(data)
    
    if hasattr(cls, '__dataclass_fields__'):
        field_values = {}
        for field_name, field_type in cls.__dataclass_fields__.items():
            if field_name in data:
                field_data = data[field_name]
                if hasattr(field_type, '__origin__') and field_type.__origin__ is list:
                    # Handle List[SomeType]
                    item_type = field_type.__args__[0]
                    field_values[field_name] = [dict_to_object(item, item_type) for item in field_data]
                elif hasattr(field_type, '__origin__') and field_type.__origin__ is Optional:
                    # Handle Optional[SomeType]
                    actual_type = field_type.__args__[0]
                    field_values[field_name] = dict_to_object(field_data, actual_type)
                elif hasattr(field_type, '__dataclass_fields__') or issubclass(field_type, (Enum, datetime)):
                    field_values[field_name] = dict_to_object(field_data, field_type)
                else:
                    field_values[field_name] = field_data
            # Handle cases where data might be missing for fields with default values
            elif field_type.default_factory:
                field_values[field_name] = field_type.default_factory()
            elif field_type.default != field_type.empty:
                field_values[field_name] = field_type.default

        return cls(**field_values)
    return data

def save_project():
    """Save current project state to a JSON file."""
    project_data = {
        "project_id": st.session_state.project_id,
        "project_name": st.session_state.project_name,
        "components": object_to_dict(st.session_state.components),
        "data_flows": object_to_dict(st.session_state.data_flows),
        "trust_boundaries": object_to_dict(st.session_state.trust_boundaries),
        "threats": object_to_dict(st.session_state.threats)
    }
    
    # Generate a unique filename or use project name
    filename = f"{st.session_state.project_name.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    
    json_data = json.dumps(project_data, indent=4)
    st.download_button(
        label="📥 Download Threat Model (JSON)",
        data=json_data,
        file_name=filename,
        mime="application/json",
        type="secondary",
        help="Download the entire threat model as a JSON file."
    )
    # Consider adding a backend storage mechanism for true enterprise persistence (e.g., S3, database)

def load_project():
    """Load project state from an uploaded JSON file."""
    st.subheader("⬆️ Upload Threat Model")
    uploaded_file = st.file_uploader("Upload a JSON file", type="json", key="upload_project_file")
    
    if uploaded_file is not None:
        try:
            bytes_data = uploaded_file.getvalue()
            project_data = json.loads(bytes_data)
            
            # Reconstruct dataclass objects
            st.session_state.project_id = project_data.get("project_id", str(uuid.uuid4()))
            st.session_state.project_name = project_data.get("project_name", "Loaded Threat Model")
            st.session_state.components = [dict_to_object(c, Component) for c in project_data.get("components", [])]
            st.session_state.data_flows = [dict_to_object(df, DataFlow) for df in project_data.get("data_flows", [])]
            st.session_state.trust_boundaries = [dict_to_object(tb, TrustBoundary) for tb in project_data.get("trust_boundaries", [])]
            st.session_state.threats = [dict_to_object(t, Threat) for t in project_data.get("threats", [])]

            # Ensure data flows are re-analyzed after load, especially if boundaries changed
            st.session_state.data_flows = analyze_trust_boundary_crossings(
                st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
            )
            
            st.success(f"✅ Project '{st.session_state.project_name}' loaded successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"❌ Error loading project: {e}. Please ensure it's a valid threat model JSON.")

# Part 5: Main App Logic and Enterprise Features
def main():
    initialize_session_state()

    st.set_page_config(
        page_title="ThreatModel Enterprise",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Apply custom CSS for enterprise look and feel
    st.markdown(f"""
        <style>
            .reportview-container {{
                background: {ENTERPRISE_THEME['background_color']};
            }}
            .sidebar .sidebar-content {{
                background: {ENTERPRISE_THEME['card_background']};
            }}
            h1, h2, h3, h4, h5, h6 {{
                color: {ENTERPRISE_THEME['text_color']};
            }}
            .stButton>button {{
                background-color: {ENTERPRISE_THEME['primary_color']};
                color: white;
                border-radius: 5px;
                border: none;
                padding: 10px 20px;
                cursor: pointer;
            }}
            .stButton>button:hover {{
                background-color: #1a649a; /* Darker shade */
            }}
            .stSelectbox, .stTextInput, .stTextArea, .stMultiSelect, .stNumberInput {{
                border: 1px solid {ENTERPRISE_THEME['border_color']};
                border-radius: 5px;
            }}
            .stAlert {{
                border-radius: 8px;
            }}
            /* Specific styles for metrics */
            div[data-testid="stMetric"] {{
                background-color: {ENTERPRISE_THEME['card_background']};
                border-left: 5px solid {ENTERPRISE_THEME['primary_color']};
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            }}
            div[data-testid="stMetric"] label {{
                color: {ENTERPRISE_THEME['text_color']};
                font-weight: bold;
                font-size: 1.1em;
            }}
            div[data-testid="stMetric"] div[data-testid="stMarkdownContainer"] p {{
                font-size: 2.2em;
                font-weight: bold;
                color: {ENTERPRISE_THEME['primary_color']};
            }}
            div[data-testid="stMetric"] .css-1qxtbh3.e16fv1bt2 {{ /* delta */
                font-size: 0.9em;
                color: {ENTERPRISE_THEME['success_color']};
            }}
        </style>
    """, unsafe_allow_html=True)

    render_header()
    render_metrics_dashboard()

    st.sidebar.title("🛠️ Navigation")
    menu = st.sidebar.radio(
        "Go To",
        [
            "🏠 Dashboard",
            "🏗️ Components",
            "🔄 Data Flows",
            "🔐 Trust Boundaries",
            "🚨 Threats",
            "🎨 Architecture Diagram",
            "⬆️ Import/Export"
        ],
        index=0 # Default to Dashboard
    )

    st.markdown("---") # Horizontal line for separation

    if menu == "🏠 Dashboard":
        st.subheader("🏠 Project Dashboard")
        st.write(f"**Project Name:** {st.session_state.project_name}")
        st.write(f"**Project ID:** {st.session_state.project_id}")
        st.write("Welcome to your Enterprise Threat Modeling platform. Use the sidebar to navigate.")
        
        # Display summary cards
        total_components = len(st.session_state.components)
        total_data_flows = len(st.session_state.data_flows)
        total_threats = len(st.session_state.threats)
        open_threats = len([t for t in st.session_state.threats if t.status == "Open"])
        critical_high_threats = len([t for t in st.session_state.threats if t.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]])
        
        st.markdown("---")
        st.subheader("Quick Overview")
        col_dash1, col_dash2, col_dash3 = st.columns(3)
        with col_dash1:
            render_professional_card("Total Components", f"{total_components}", "🏗️", "primary")
        with col_dash2:
            render_professional_card("Total Data Flows", f"{total_data_flows}", "🔄", "info")
        with col_dash3:
            render_professional_card("Total Threats", f"{total_threats}", "🚨", "warning")
        
        col_dash4, col_dash5, col_dash6 = st.columns(3)
        with col_dash4:
            render_professional_card("Open Threats", f"{open_threats}", "⚠️", "error")
        with col_dash5:
            render_professional_card("Critical/High Threats", f"{critical_high_threats}", "🔥", "error")
        with col_dash6:
            # Example: calculate average risk score
            if total_threats > 0:
                avg_risk = sum(t.risk_score for t in st.session_state.threats) / total_threats
                render_professional_card("Average Risk Score", f"{avg_risk:.2f}", "📈", "success")
            else:
                render_professional_card("Average Risk Score", "N/A", "📈", "success")

        st.markdown("---")
        st.subheader("Threats by Severity")
        if st.session_state.threats:
            severity_counts = pd.DataFrame([t.severity.value for t in st.session_state.threats], columns=['Severity']).value_counts().reset_index(name='Count')
            severity_order = [s.value for s in ThreatSeverity] # Maintain order
            severity_counts['Severity'] = pd.Categorical(severity_counts['Severity'], categories=severity_order, ordered=True)
            severity_counts = severity_counts.sort_values('Severity')

            fig_pie = px.pie(severity_counts, values='Count', names='Severity', title='Threats by Severity',
                             color='Severity',
                             color_discrete_map={
                                 ThreatSeverity.CRITICAL.value: '#d62728', # Red
                                 ThreatSeverity.HIGH.value: '#ff7f0e',    # Orange
                                 ThreatSeverity.MEDIUM.value: '#ff9800',  # Amber
                                 ThreatSeverity.LOW.value: '#2ca02c',     # Green
                                 ThreatSeverity.INFO.value: '#17a2b8'     # Cyan
                             })
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("Add some threats to see this chart!")

    elif menu == "🏗️ Components":
        render_component_form()
        st.markdown("---")
        render_component_table()

    elif menu == "🔄 Data Flows":
        render_data_flow_form()
        st.markdown("---")
        st.subheader("📋 Data Flow Inventory")
        if st.session_state.data_flows:
            data_flow_data = []
            for flow in st.session_state.data_flows:
                data_flow_data.append({
                    "ID": flow.id,
                    "Source": flow.source,
                    "Target": flow.target,
                    "Data Type": flow.data_type,
                    "Protocol": flow.protocol,
                    "Port": flow.port if flow.port else "N/A",
                    "Encrypted": "Yes" if flow.encryption else "No",
                    "Auth Required": "Yes" if flow.authentication_required else "No",
                    "Data Classification": flow.data_classification,
                    "Crosses Trust Boundary": "Yes" if flow.crosses_trust_boundary else "No",
                    "Boundary Crossed": flow.trust_boundary_crossed if flow.trust_boundary_crossed else "N/A",
                    "Description": flow.description
                })
            df_flows = pd.DataFrame(data_flow_data)
            st.dataframe(df_flows, use_container_width=True, hide_index=True)
            
            # Data Flow management actions (similar to components)
            st.markdown("---")
            st.subheader("Data Flow Management Actions")
            col_flow_del, col_flow_edit = st.columns(2)

            with col_flow_del:
                flow_to_delete_id = st.selectbox(
                    "Select Data Flow to Delete",
                    [""] + [f.id for f in st.session_state.data_flows],
                    format_func=lambda x: next((f"{fl.source} -> {fl.target} (ID: {fl.id})" for fl in st.session_state.data_flows if fl.id == x), x),
                    key="delete_flow_select"
                )
                if st.button("🗑️ Delete Selected Data Flow", type="secondary", disabled=flow_to_delete_id == ""):
                    if flow_to_delete_id:
                        # Remove threats associated with this data flow
                        st.session_state.threats = [
                            t for t in st.session_state.threats
                            if flow_to_delete_id not in t.affected_data_flows
                        ]
                        st.session_state.data_flows = [f for f in st.session_state.data_flows if f.id != flow_to_delete_id]
                        st.success("✅ Data flow deleted.")
                        st.rerun()
            with col_flow_edit:
                flow_to_edit_id = st.selectbox(
                    "Select Data Flow to Edit",
                    [""] + [f.id for f in st.session_state.data_flows],
                    format_func=lambda x: next((f"{fl.source} -> {fl.target} (ID: {fl.id})" for fl in st.session_state.data_flows if fl.id == x), x),
                    key="edit_flow_select"
                )
                if flow_to_edit_id:
                    selected_flow = next((f for f in st.session_state.data_flows if f.id == flow_to_edit_id), None)
                    if selected_flow:
                        with st.expander(f"Edit Data Flow: {selected_flow.source} -> {selected_flow.target}"):
                            edit_data_flow_form(selected_flow)
        else:
            st.info("No data flows added yet.")

    elif menu == "🔐 Trust Boundaries":
        render_trust_boundary_form()
        st.markdown("---")
        st.subheader("Summary of Trust Boundaries")
        if st.session_state.trust_boundaries:
            for boundary in st.session_state.trust_boundaries:
                components_list = ", ".join(boundary.components) if boundary.components else "None"
                controls_list = ", ".join(boundary.controls) if boundary.controls else "None"
                compliance_list = ", ".join(boundary.compliance_requirements) if boundary.compliance_requirements else "None"
                
                content = f"""
                <p><b>Type:</b> {boundary.boundary_type}</p>
                <p><b>Description:</b> {boundary.description}</p>
                <p><b>Components:</b> {components_list}</p>
                <p><b>Controls:</b> {controls_list}</p>
                <p><b>Compliance:</b> {compliance_list}</p>
                """
                render_professional_card(
                    f"{boundary.name}",
                    content,
                    icon="🔒",
                    color="success" if boundary.security_level == SecurityLevel.HIGH or boundary.security_level == SecurityLevel.CRITICAL else "warning"
                )
        else:
            st.info("No trust boundaries defined yet.")

    elif menu == "🚨 Threats":
        render_threat_management()

    elif menu == "🎨 Architecture Diagram":
        render_enhanced_architecture_diagram()

    elif menu == "⬆️ Import/Export":
        st.markdown("---")
        load_project()
        st.markdown("---")
        save_project()
        st.markdown("---")
        st.subheader("Generate Report")
        st.info("This feature would generate a comprehensive PDF/DocX report including diagrams, component inventory, and threat details.")
        if st.button("Generate Comprehensive Report", key="generate_report_button"):
            st.write("Generating report... (Feature Under Development)")
            # In a real app, this would trigger a backend process to generate the report

def edit_data_flow_form(flow: DataFlow):
    """Renders a form to edit an existing data flow."""
    current_component_names = [c.name for c in st.session_state.components]
    with st.form(f"edit_flow_form_{flow.id}"):
        edited_source = st.selectbox("Source Component*", current_component_names, index=current_component_names.index(flow.source), key=f"edit_f_source_{flow.id}")
        edited_target = st.selectbox("Target Component*", current_component_names, index=current_component_names.index(flow.target), key=f"edit_f_target_{flow.id}")
        edited_data_type = st.text_input("Data Type*", flow.data_type, key=f"edit_f_data_type_{flow.id}")
        edited_protocol = st.selectbox("Protocol*", ["HTTPS", "HTTP", "TLS", "TCP", "UDP", "WebSocket", "gRPC", "SFTP", "SSH"], index=["HTTPS", "HTTP", "TLS", "TCP", "UDP", "WebSocket", "gRPC", "SFTP", "SSH"].index(flow.protocol), key=f"edit_f_protocol_{flow.id}")
        edited_port = st.number_input("Port", min_value=1, max_value=65535, value=flow.port or 443, key=f"edit_f_port_{flow.id}")
        edited_data_classification = st.selectbox("Data Classification", ["Public", "Internal", "Confidential", "Restricted"], index=["Public", "Internal", "Confidential", "Restricted"].index(flow.data_classification), key=f"edit_f_data_class_{flow.id}")
        edited_encryption = st.checkbox("Encrypted in Transit", value=flow.encryption, key=f"edit_f_encrypt_{flow.id}")
        edited_authentication = st.checkbox("Authentication Required", value=flow.authentication_required, key=f"edit_f_auth_{flow.id}")
        edited_description = st.text_area("Description", flow.description, key=f"edit_f_desc_{flow.id}")

        update_submitted = st.form_submit_button("💾 Update Data Flow", type="primary")

        if update_submitted:
            if edited_source == edited_target:
                st.error("❌ Source and target cannot be the same component.")
                return
            
            # Check for duplicate flow (same source, target, data type, protocol) excluding itself
            if any(f.source == edited_source and f.target == edited_target and f.data_type == edited_data_type and f.protocol == edited_protocol and f.id != flow.id
                   for f in st.session_state.data_flows):
                st.error(f"❌ A similar data flow from '{edited_source}' to '{edited_target}' with data type '{edited_data_type}' and protocol '{edited_protocol}' already exists.")
                return

            flow.source = edited_source
            flow.target = edited_target
            flow.data_type = edited_data_type
            flow.protocol = edited_protocol
            flow.port = edited_port
            flow.data_classification = edited_data_classification
            flow.encryption = edited_encryption
            flow.authentication_required = edited_authentication
            flow.description = edited_description
            flow.updated_at = datetime.now()

            # Re-analyze boundary crossings after updating a flow
            st.session_state.data_flows = analyze_trust_boundary_crossings(
                st.session_state.components, st.session_state.data_flows, st.session_state.trust_boundaries
            )
            st.success(f"✅ Data flow from '{edited_source}' to '{edited_target}' updated successfully!")
            st.rerun()

if __name__ == "__main__":
    main()
