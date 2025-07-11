import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from dataclasses import dataclass
from typing import List, Dict, Tuple
import json

# Initialize session state
if 'components' not in st.session_state:
    st.session_state.components = []
if 'data_flows' not in st.session_state:
    st.session_state.data_flows = []
if 'trust_boundaries' not in st.session_state:
    st.session_state.trust_boundaries = []
if 'threats' not in st.session_state:
    st.session_state.threats = []

@dataclass
class Component:
    name: str
    type: str
    description: str
    x: float
    y: float

@dataclass
class DataFlow:
    source: str
    target: str
    data_type: str
    protocol: str
    description: str

@dataclass
class TrustBoundary:
    name: str
    components: List[str]
    security_level: str
    description: str

@dataclass
class Threat:
    id: str
    name: str
    description: str
    affected_components: List[str]
    stride_category: str
    severity: str
    mitigation: str

# Predefined threat patterns
THREAT_PATTERNS = {
    "Web Application": [
        Threat("T001", "SQL Injection", "Malicious SQL code injection through user inputs", 
               ["Database"], "Tampering", "High", "Use parameterized queries and input validation"),
        Threat("T002", "Cross-Site Scripting (XSS)", "Malicious scripts executed in user browsers", 
               ["Web Server"], "Tampering", "Medium", "Implement output encoding and CSP headers"),
        Threat("T003", "Authentication Bypass", "Unauthorized access to protected resources", 
               ["Authentication Service"], "Spoofing", "High", "Implement strong authentication mechanisms"),
    ],
    "API": [
        Threat("T004", "API Rate Limiting Bypass", "Overwhelming API with excessive requests", 
               ["API Gateway"], "Denial of Service", "Medium", "Implement proper rate limiting and throttling"),
        Threat("T005", "Insecure Direct Object References", "Unauthorized access to objects", 
               ["API Server"], "Information Disclosure", "High", "Implement proper authorization checks"),
    ],
    "Database": [
        Threat("T006", "Data Exposure", "Unauthorized access to sensitive data", 
               ["Database"], "Information Disclosure", "High", "Implement encryption at rest and in transit"),
        Threat("T007", "Privilege Escalation", "Gaining higher privileges than intended", 
               ["Database"], "Elevation of Privilege", "High", "Implement principle of least privilege"),
    ],
    "Network": [
        Threat("T008", "Man-in-the-Middle Attack", "Interception of network communications", 
               ["Network"], "Tampering", "High", "Use TLS/SSL encryption for all communications"),
        Threat("T009", "Network Sniffing", "Unauthorized monitoring of network traffic", 
               ["Network"], "Information Disclosure", "Medium", "Implement network segmentation and encryption"),
    ]
}

# Sample architectures
SAMPLE_ARCHITECTURES = {
    "Online Banking": {
        "components": [
            Component("User Browser", "External Entity", "Customer's web browser", 1, 5),
            Component("Load Balancer", "Process", "Distributes incoming requests", 2, 5),
            Component("Web Server", "Process", "Handles HTTP requests", 3, 5),
            Component("App Server", "Process", "Business logic processing", 4, 5),
            Component("Auth Service", "Process", "Authentication and authorization", 4, 6),
            Component("Database", "Data Store", "Customer and transaction data", 5, 5),
            Component("Payment Gateway", "External Entity", "External payment processor", 5, 6),
            Component("SMS Service", "External Entity", "SMS notification service", 3, 6),
        ],
        "data_flows": [
            DataFlow("User Browser", "Load Balancer", "HTTPS Request", "HTTPS", "User login/transaction requests"),
            DataFlow("Load Balancer", "Web Server", "HTTP Request", "HTTP", "Forwarded user requests"),
            DataFlow("Web Server", "App Server", "API Call", "HTTPS", "Business logic requests"),
            DataFlow("App Server", "Auth Service", "Auth Request", "HTTPS", "Authentication validation"),
            DataFlow("App Server", "Database", "Query", "TLS", "Data retrieval/storage"),
            DataFlow("App Server", "Payment Gateway", "Payment Request", "HTTPS", "Payment processing"),
            DataFlow("App Server", "SMS Service", "SMS Request", "HTTPS", "Transaction notifications"),
        ],
        "trust_boundaries": [
            TrustBoundary("DMZ", ["Load Balancer", "Web Server"], "Medium", "Public-facing components"),
            TrustBoundary("Internal Network", ["App Server", "Auth Service"], "High", "Internal business logic"),
            TrustBoundary("Database Zone", ["Database"], "High", "Sensitive data storage"),
            TrustBoundary("External Services", ["Payment Gateway", "SMS Service"], "Low", "Third-party services"),
        ]
    },
    "Online Order Processing": {
        "components": [
            Component("Customer App", "External Entity", "Mobile/Web application", 1, 3),
            Component("API Gateway", "Process", "API request routing", 2, 3),
            Component("Order Service", "Process", "Order processing logic", 3, 3),
            Component("Inventory Service", "Process", "Stock management", 3, 4),
            Component("Payment Service", "Process", "Payment processing", 3, 2),
            Component("Notification Service", "Process", "Customer notifications", 4, 3),
            Component("Order Database", "Data Store", "Order information", 4, 4),
            Component("User Database", "Data Store", "Customer information", 4, 2),
            Component("Email Service", "External Entity", "Email notifications", 5, 3),
        ],
        "data_flows": [
            DataFlow("Customer App", "API Gateway", "Order Request", "HTTPS", "Customer order submission"),
            DataFlow("API Gateway", "Order Service", "Order Data", "HTTPS", "Order processing request"),
            DataFlow("Order Service", "Inventory Service", "Stock Check", "HTTPS", "Inventory verification"),
            DataFlow("Order Service", "Payment Service", "Payment Request", "HTTPS", "Payment processing"),
            DataFlow("Order Service", "Notification Service", "Notification Request", "HTTPS", "Order status updates"),
            DataFlow("Order Service", "Order Database", "Order Data", "TLS", "Order storage"),
            DataFlow("Payment Service", "User Database", "User Data", "TLS", "User information retrieval"),
            DataFlow("Notification Service", "Email Service", "Email Request", "HTTPS", "Email notifications"),
        ],
        "trust_boundaries": [
            TrustBoundary("Public Zone", ["API Gateway"], "Medium", "Public-facing API"),
            TrustBoundary("Service Layer", ["Order Service", "Inventory Service", "Payment Service", "Notification Service"], "High", "Internal microservices"),
            TrustBoundary("Data Layer", ["Order Database", "User Database"], "High", "Sensitive data storage"),
            TrustBoundary("External Services", ["Email Service"], "Low", "Third-party services"),
        ]
    }
}

def create_architecture_diagram(components, data_flows, trust_boundaries):
    """Create a visual representation of the architecture"""
    fig = go.Figure()
    
    # Add trust boundaries as shapes
    colors = ['lightblue', 'lightgreen', 'lightyellow', 'lightpink', 'lightgray']
    for i, boundary in enumerate(trust_boundaries):
        boundary_components = [c for c in components if c.name in boundary.components]
        if boundary_components:
            min_x = min(c.x for c in boundary_components) - 0.3
            max_x = max(c.x for c in boundary_components) + 0.3
            min_y = min(c.y for c in boundary_components) - 0.3
            max_y = max(c.y for c in boundary_components) + 0.3
            
            fig.add_shape(
                type="rect",
                x0=min_x, y0=min_y,
                x1=max_x, y1=max_y,
                fillcolor=colors[i % len(colors)],
                opacity=0.3,
                line=dict(width=2, color=colors[i % len(colors)]),
                layer="below"
            )
            
            # Add boundary label
            fig.add_annotation(
                x=min_x + 0.1,
                y=max_y - 0.1,
                text=boundary.name,
                showarrow=False,
                font=dict(size=10, color="black"),
                bgcolor="white",
                bordercolor="black",
                borderwidth=1
            )
    
    # Add components as nodes
    component_colors = {
        'External Entity': 'red',
        'Process': 'blue',
        'Data Store': 'green'
    }
    
    for component in components:
        fig.add_trace(go.Scatter(
            x=[component.x],
            y=[component.y],
            mode='markers+text',
            marker=dict(
                size=20,
                color=component_colors.get(component.type, 'gray'),
                symbol='square' if component.type == 'Data Store' else 'circle'
            ),
            text=component.name,
            textposition="bottom center",
            name=component.type,
            hovertemplate=f"<b>{component.name}</b><br>Type: {component.type}<br>Description: {component.description}<extra></extra>"
        ))
    
    # Add data flows as arrows
    for flow in data_flows:
        source_comp = next((c for c in components if c.name == flow.source), None)
        target_comp = next((c for c in components if c.name == flow.target), None)
        
        if source_comp and target_comp:
            fig.add_annotation(
                x=target_comp.x,
                y=target_comp.y,
                ax=source_comp.x,
                ay=source_comp.y,
                xref="x",
                yref="y",
                axref="x",
                ayref="y",
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=2,
                arrowcolor="black",
                text=flow.data_type,
                textangle=0,
                font=dict(size=8)
            )
    
    fig.update_layout(
        title="System Architecture",
        showlegend=True,
        width=800,
        height=600,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    
    return fig

def analyze_threats(components, data_flows, trust_boundaries):
    """Analyze the architecture and generate relevant threats"""
    identified_threats = []
    
    # Component-based threat analysis
    for component in components:
        component_type = component.type
        if component_type in ["Process", "Data Store"]:
            if "Web" in component.name or "API" in component.name:
                identified_threats.extend([t for t in THREAT_PATTERNS["Web Application"] if component.name in t.affected_components or component.type in t.affected_components])
                identified_threats.extend([t for t in THREAT_PATTERNS["API"] if component.name in t.affected_components or component.type in t.affected_components])
            elif "Database" in component.name:
                identified_threats.extend([t for t in THREAT_PATTERNS["Database"] if component.name in t.affected_components or "Database" in t.affected_components])
    
    # Data flow-based threat analysis
    for flow in data_flows:
        if flow.protocol in ["HTTP", "TCP"]:
            network_threats = [t for t in THREAT_PATTERNS["Network"]]
            for threat in network_threats:
                new_threat = Threat(
                    threat.id,
                    threat.name,
                    threat.description,
                    [flow.source, flow.target],
                    threat.stride_category,
                    threat.severity,
                    threat.mitigation
                )
                identified_threats.append(new_threat)
    
    # Trust boundary-based threat analysis
    for boundary in trust_boundaries:
        if boundary.security_level == "Low":
            # Add threats related to low trust boundaries
            for component_name in boundary.components:
                threat = Threat(
                    f"TB_{boundary.name}",
                    f"Trust Boundary Violation - {boundary.name}",
                    f"Potential security risks due to low trust level in {boundary.name}",
                    [component_name],
                    "Elevation of Privilege",
                    "Medium",
                    "Implement additional security controls for low-trust boundaries"
                )
                identified_threats.append(threat)
    
    return identified_threats

def main():
    st.set_page_config(page_title="Threat Modeling Teacher", layout="wide")
    
    st.title("🔒 Threat Modeling Teaching Application")
    st.markdown("Learn threat modeling by creating architectures and analyzing security threats")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Choose a page", [
        "Architecture Builder",
        "Threat Analysis", 
        "Sample: Online Banking",
        "Sample: Order Processing",
        "Learning Resources"
    ])
    
    if page == "Architecture Builder":
        st.header("🏗️ Architecture Builder")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.subheader("Add Components")
            
            with st.form("add_component"):
                comp_name = st.text_input("Component Name")
                comp_type = st.selectbox("Type", ["External Entity", "Process", "Data Store"])
                comp_desc = st.text_area("Description")
                comp_x = st.slider("X Position", 1, 10, 5)
                comp_y = st.slider("Y Position", 1, 10, 5)
                
                if st.form_submit_button("Add Component"):
                    new_comp = Component(comp_name, comp_type, comp_desc, comp_x, comp_y)
                    st.session_state.components.append(new_comp)
                    st.success(f"Added {comp_name}")
            
            st.subheader("Add Data Flows")
            
            if st.session_state.components:
                component_names = [c.name for c in st.session_state.components]
                
                with st.form("add_dataflow"):
                    source = st.selectbox("Source", component_names)
                    target = st.selectbox("Target", component_names)
                    data_type = st.text_input("Data Type")
                    protocol = st.selectbox("Protocol", ["HTTPS", "HTTP", "TLS", "TCP", "UDP"])
                    flow_desc = st.text_area("Flow Description")
                    
                    if st.form_submit_button("Add Data Flow"):
                        new_flow = DataFlow(source, target, data_type, protocol, flow_desc)
                        st.session_state.data_flows.append(new_flow)
                        st.success(f"Added data flow from {source} to {target}")
            
            st.subheader("Add Trust Boundaries")
            
            if st.session_state.components:
                with st.form("add_boundary"):
                    boundary_name = st.text_input("Boundary Name")
                    selected_components = st.multiselect("Components", component_names)
                    security_level = st.selectbox("Security Level", ["Low", "Medium", "High"])
                    boundary_desc = st.text_area("Boundary Description")
                    
                    if st.form_submit_button("Add Trust Boundary"):
                        new_boundary = TrustBoundary(boundary_name, selected_components, security_level, boundary_desc)
                        st.session_state.trust_boundaries.append(new_boundary)
                        st.success(f"Added trust boundary: {boundary_name}")
        
        with col2:
            st.subheader("Architecture Visualization")
            
            if st.session_state.components:
                fig = create_architecture_diagram(
                    st.session_state.components,
                    st.session_state.data_flows,
                    st.session_state.trust_boundaries
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Add components to see the architecture diagram")
            
            # Clear architecture button
            if st.button("Clear Architecture"):
                st.session_state.components = []
                st.session_state.data_flows = []
                st.session_state.trust_boundaries = []
                st.success("Architecture cleared!")
    
    elif page == "Threat Analysis":
        st.header("🔍 Threat Analysis")
        
        if st.session_state.components:
            if st.button("Analyze Threats"):
                threats = analyze_threats(
                    st.session_state.components,
                    st.session_state.data_flows,
                    st.session_state.trust_boundaries
                )
                st.session_state.threats = threats
            
            if st.session_state.threats:
                st.subheader("Identified Threats")
                
                # Create threat summary
                threat_df = pd.DataFrame([
                    {
                        "ID": t.id,
                        "Name": t.name,
                        "STRIDE": t.stride_category,
                        "Severity": t.severity,
                        "Affected Components": ", ".join(t.affected_components)
                    }
                    for t in st.session_state.threats
                ])
                
                st.dataframe(threat_df)
                
                # Detailed threat analysis
                st.subheader("Detailed Threat Information")
                
                for threat in st.session_state.threats:
                    with st.expander(f"{threat.name} - {threat.severity} Severity"):
                        st.write(f"**Description:** {threat.description}")
                        st.write(f"**STRIDE Category:** {threat.stride_category}")
                        st.write(f"**Affected Components:** {', '.join(threat.affected_components)}")
                        st.write(f"**Mitigation:** {threat.mitigation}")
                
                # Threat statistics
                col1, col2 = st.columns(2)
                
                with col1:
                    severity_counts = pd.DataFrame([t.severity for t in st.session_state.threats]).value_counts()
                    fig_severity = px.pie(
                        values=severity_counts.values,
                        names=severity_counts.index,
                        title="Threats by Severity"
                    )
                    st.plotly_chart(fig_severity, use_container_width=True)
                
                with col2:
                    stride_counts = pd.DataFrame([t.stride_category for t in st.session_state.threats]).value_counts()
                    fig_stride = px.bar(
                        x=stride_counts.index,
                        y=stride_counts.values,
                        title="Threats by STRIDE Category"
                    )
                    st.plotly_chart(fig_stride, use_container_width=True)
        else:
            st.info("Create an architecture first to analyze threats")
    
    elif page == "Sample: Online Banking":
        st.header("🏦 Sample: Online Banking Application")
        
        if st.button("Load Banking Sample"):
            sample = SAMPLE_ARCHITECTURES["Online Banking"]
            st.session_state.components = sample["components"]
            st.session_state.data_flows = sample["data_flows"]
            st.session_state.trust_boundaries = sample["trust_boundaries"]
            st.success("Banking sample loaded!")
        
        if st.session_state.components:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                fig = create_architecture_diagram(
                    st.session_state.components,
                    st.session_state.data_flows,
                    st.session_state.trust_boundaries
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader("Key Security Considerations")
                st.write("• **Authentication**: Multi-factor authentication required")
                st.write("• **Encryption**: All data encrypted in transit and at rest")
                st.write("• **Network Security**: DMZ deployment for web-facing components")
                st.write("• **Data Protection**: PCI DSS compliance for payment data")
                st.write("• **Monitoring**: Real-time fraud detection and monitoring")
        
        st.subheader("Architecture Description")
        st.write("""
        This online banking application demonstrates a typical three-tier architecture with multiple security layers:
        
        **External Zone**: Customer browsers interact with the system through HTTPS
        **DMZ**: Load balancer and web servers handle public traffic
        **Internal Network**: Application servers and authentication services process business logic
        **Database Zone**: Highly secured database layer with sensitive customer data
        **External Services**: Third-party integrations for payments and notifications
        """)
    
    elif page == "Sample: Order Processing":
        st.header("🛒 Sample: Order Processing Application")
        
        if st.button("Load Order Processing Sample"):
            sample = SAMPLE_ARCHITECTURES["Online Order Processing"]
            st.session_state.components = sample["components"]
            st.session_state.data_flows = sample["data_flows"]
            st.session_state.trust_boundaries = sample["trust_boundaries"]
            st.success("Order processing sample loaded!")
        
        if st.session_state.components:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                fig = create_architecture_diagram(
                    st.session_state.components,
                    st.session_state.data_flows,
                    st.session_state.trust_boundaries
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader("Key Security Considerations")
                st.write("• **API Security**: Rate limiting and authentication")
                st.write("• **Microservices**: Service-to-service authentication")
                st.write("• **Data Validation**: Input validation across all services")
                st.write("• **Payment Security**: PCI compliance and tokenization")
                st.write("• **Audit Trail**: Comprehensive logging and monitoring")
        
        st.subheader("Architecture Description")
        st.write("""
        This order processing application demonstrates a microservices architecture with clear service boundaries:
        
        **Public Zone**: API Gateway serves as the single entry point
        **Service Layer**: Independent microservices for different business functions
        **Data Layer**: Separate databases for different service domains
        **External Services**: Third-party integrations for notifications and communications
        """)
    
    elif page == "Learning Resources":
        st.header("📚 Learning Resources")
        
        st.subheader("STRIDE Methodology")
        st.write("""
        STRIDE is a threat modeling methodology that categorizes threats into six categories:
        
        • **Spoofing**: Impersonating something or someone else
        • **Tampering**: Modifying data or code
        • **Repudiation**: Claiming to have not performed an action
        • **Information Disclosure**: Exposing information to unauthorized individuals
        • **Denial of Service**: Denying or degrading service to valid users
        • **Elevation of Privilege**: Gaining capabilities without proper authorization
        """)
        
        st.subheader("Trust Boundaries")
        st.write("""
        Trust boundaries represent the border between different levels of trust in a system:
        
        • **High Trust**: Internal systems with strong security controls
        • **Medium Trust**: Protected systems with some exposure
        • **Low Trust**: External systems or public-facing components
        
        Data crossing trust boundaries should be validated and secured appropriately.
        """)
        
        st.subheader("Component Types")
        st.write("""
        • **External Entity**: Users, systems, or processes outside your control
        • **Process**: Running code or functionality (applications, services)
        • **Data Store**: Where data is stored (databases, files, queues)
        """)
        
        st.subheader("Best Practices")
        st.write("""
        1. **Start Simple**: Begin with a high-level architecture
        2. **Identify Assets**: What needs protection?
        3. **Map Trust Boundaries**: Where do trust levels change?
        4. **Analyze Data Flows**: How does data move through the system?
        5. **Apply STRIDE**: Systematically consider each threat category
        6. **Prioritize**: Focus on high-impact, high-likelihood threats
        7. **Mitigate**: Design controls to address identified threats
        8. **Validate**: Test and verify your security measures
        """)

if __name__ == "__main__":
    main()