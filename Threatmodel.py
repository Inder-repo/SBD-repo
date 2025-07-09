import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np

# Page configuration
st.set_page_config(
    page_title="SecureBank Threat Model",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
    }
    
    .boundary-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .threat-item {
        background: rgba(255, 255, 255, 0.1);
        padding: 0.8rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid #ff6b6b;
    }
    
    .mitigation-item {
        background: rgba(255, 255, 255, 0.1);
        padding: 0.8rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid #51cf66;
    }
    
    .risk-critical { background-color: #dc3545; color: white; padding: 0.3rem; border-radius: 5px; }
    .risk-high { background-color: #fd7e14; color: white; padding: 0.3rem; border-radius: 5px; }
    .risk-medium { background-color: #ffc107; color: black; padding: 0.3rem; border-radius: 5px; }
    .risk-low { background-color: #28a745; color: white; padding: 0.3rem; border-radius: 5px; }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    
    .stride-category {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    
    .mitigation-card {
        background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# Data structure for the threat model
@st.cache_data
def load_threat_data():
    threats_data = {
        'Boundary 1: Internet → DMZ': {
            'description': 'Zero Trust Zone - External users accessing web-facing components',
            'components': ['Internet Users', 'Web Application Firewall', 'Load Balancer'],
            'threats': [
                {'id': 'T1.1', 'name': 'Phishing Attacks', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical'},
                {'id': 'T1.2', 'name': 'Domain Spoofing', 'category': 'Spoofing', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T1.3', 'name': 'SSL Certificate Spoofing', 'category': 'Spoofing', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
                {'id': 'T1.4', 'name': 'MITM Attacks', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High'},
                {'id': 'T1.5', 'name': 'Session Hijacking (XSS)', 'category': 'Tampering', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T1.6', 'name': 'CSRF Attacks', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High'},
                {'id': 'T1.7', 'name': 'Transaction Repudiation', 'category': 'Repudiation', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
                {'id': 'T1.8', 'name': 'Log Manipulation', 'category': 'Repudiation', 'likelihood': 2, 'impact': 3, 'risk_score': 6, 'risk_level': 'Medium'},
                {'id': 'T1.9', 'name': 'Error Message Disclosure', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T1.10', 'name': 'Username Enumeration', 'category': 'Information Disclosure', 'likelihood': 4, 'impact': 3, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T1.11', 'name': 'Timing Attacks', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 3, 'risk_score': 6, 'risk_level': 'Medium'},
                {'id': 'T1.12', 'name': 'Brute Force Attacks', 'category': 'Denial of Service', 'likelihood': 4, 'impact': 3, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T1.13', 'name': 'DDoS Attacks', 'category': 'Denial of Service', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T1.14', 'name': 'Resource Exhaustion', 'category': 'Denial of Service', 'likelihood': 3, 'impact': 3, 'risk_score': 9, 'risk_level': 'Medium'},
                {'id': 'T1.15', 'name': 'SQL Injection', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T1.16', 'name': 'Authentication Bypass', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T1.17', 'name': 'Privilege Escalation', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
            ],
            'mitigations': [
                {'threat_id': 'T1.1', 'type': 'Preventive', 'control': 'Extended Validation SSL certificates with clear visual indicators'},
                {'threat_id': 'T1.1', 'type': 'Detective', 'control': 'Certificate transparency logs and brand monitoring services'},
                {'threat_id': 'T1.1', 'type': 'Responsive', 'control': 'Rapid takedown procedures and customer notifications'},
                {'threat_id': 'T1.4', 'type': 'Preventive', 'control': 'TLS 1.3 enforcement, secure session cookies'},
                {'threat_id': 'T1.4', 'type': 'Detective', 'control': 'SSL/TLS monitoring, session anomaly detection'},
                {'threat_id': 'T1.4', 'type': 'Responsive', 'control': 'Automatic session termination, IP blocking'},
                {'threat_id': 'T1.15', 'type': 'Preventive', 'control': 'Parameterized queries, input validation, WAF rules'},
                {'threat_id': 'T1.15', 'type': 'Detective', 'control': 'Database query monitoring, anomaly detection'},
                {'threat_id': 'T1.15', 'type': 'Responsive', 'control': 'Automatic account suspension, query blocking'},
                {'threat_id': 'T1.12', 'type': 'Preventive', 'control': 'Rate limiting, account lockout, CAPTCHA'},
                {'threat_id': 'T1.12', 'type': 'Detective', 'control': 'Failed login monitoring, behavioral analysis'},
                {'threat_id': 'T1.12', 'type': 'Responsive', 'control': 'Automatic IP blocking, account suspension'},
            ]
        },
        'Boundary 2: DMZ → Internal': {
            'description': 'Web tier to Application tier - Authenticated requests only',
            'components': ['Web Servers (DMZ)', 'Application Servers', 'Authentication Services'],
            'threats': [
                {'id': 'T2.1', 'name': 'Lateral Movement', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T2.2', 'name': 'API Abuse', 'category': 'Tampering', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T2.3', 'name': 'Internal Service Spoofing', 'category': 'Spoofing', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
                {'id': 'T2.4', 'name': 'Session Token Theft', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T2.5', 'name': 'Internal DoS', 'category': 'Denial of Service', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
            ],
            'mitigations': [
                {'threat_id': 'T2.1', 'type': 'Preventive', 'control': 'Network segmentation, micro-segmentation, zero-trust architecture'},
                {'threat_id': 'T2.1', 'type': 'Detective', 'control': 'Network traffic analysis, behavioral monitoring'},
                {'threat_id': 'T2.1', 'type': 'Responsive', 'control': 'Network isolation, credential rotation'},
                {'threat_id': 'T2.2', 'type': 'Preventive', 'control': 'API gateway, OAuth 2.0, rate limiting'},
                {'threat_id': 'T2.2', 'type': 'Detective', 'control': 'API monitoring, behavioral analysis'},
                {'threat_id': 'T2.2', 'type': 'Responsive', 'control': 'API throttling, token revocation'},
            ]
        },
        'Boundary 3: Application → Database': {
            'description': 'Application tier to Database tier - Authorized connections only',
            'components': ['Database Servers', 'Data Access Layer', 'Connection Pooling'],
            'threats': [
                {'id': 'T3.1', 'name': 'Database Injection', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'Critical'},
                {'id': 'T3.2', 'name': 'Credential Stuffing', 'category': 'Elevation of Privilege', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
                {'id': 'T3.3', 'name': 'Data Exfiltration', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T3.4', 'name': 'Unauthorized Data Access', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T3.5', 'name': 'Data Corruption', 'category': 'Tampering', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
                {'id': 'T3.6', 'name': 'Connection Hijacking', 'category': 'Spoofing', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
            ],
            'mitigations': [
                {'threat_id': 'T3.1', 'type': 'Preventive', 'control': 'Parameterized queries, stored procedures, input validation'},
                {'threat_id': 'T3.1', 'type': 'Detective', 'control': 'Database activity monitoring, query analysis'},
                {'threat_id': 'T3.1', 'type': 'Responsive', 'control': 'Connection termination, automated blocking'},
                {'threat_id': 'T3.3', 'type': 'Preventive', 'control': 'Database encryption, access controls, DLP'},
                {'threat_id': 'T3.3', 'type': 'Detective', 'control': 'Data loss prevention, audit logging'},
                {'threat_id': 'T3.3', 'type': 'Responsive', 'control': 'Data forensics, incident response'},
            ]
        },
        'Boundary 4: Database → Core Banking': {
            'description': 'Highest security - Encrypted connections to core financial systems',
            'components': ['Core Banking System', 'Transaction Processing', 'Account Management'],
            'threats': [
                {'id': 'T4.1', 'name': 'Financial Fraud', 'category': 'Tampering', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T4.2', 'name': 'Regulatory Compliance Breach', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T4.3', 'name': 'Core System Compromise', 'category': 'Elevation of Privilege', 'likelihood': 1, 'impact': 5, 'risk_score': 5, 'risk_level': 'Critical'},
                {'id': 'T4.4', 'name': 'Transaction Manipulation', 'category': 'Tampering', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T4.5', 'name': 'Double Spending', 'category': 'Tampering', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'T4.6', 'name': 'Account Takeover', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
            ],
            'mitigations': [
                {'threat_id': 'T4.1', 'type': 'Preventive', 'control': 'Multi-party controls, HSM, fraud detection rules'},
                {'threat_id': 'T4.1', 'type': 'Detective', 'control': 'Real-time fraud monitoring, behavioral analytics'},
                {'threat_id': 'T4.1', 'type': 'Responsive', 'control': 'Transaction reversal, account freeze, investigation'},
                {'threat_id': 'T4.4', 'type': 'Preventive', 'control': 'Atomic transactions, digital signatures, checksums'},
                {'threat_id': 'T4.4', 'type': 'Detective', 'control': 'Transaction monitoring, reconciliation'},
                {'threat_id': 'T4.4', 'type': 'Responsive', 'control': 'Transaction holds, manual review'},
            ]
        },
        'External Integrations': {
            'description': 'Third-party services with specific compliance requirements',
            'components': ['Payment Processors', 'Credit Bureaus', 'SMS/Email Services', 'Third-Party Auth'],
            'threats': [
                {'id': 'E1.1', 'name': 'PCI Compliance Breach', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical'},
                {'id': 'E1.2', 'name': 'Data Sharing Violation', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
                {'id': 'E1.3', 'name': 'Communication Interception', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 3, 'risk_score': 6, 'risk_level': 'Medium'},
                {'id': 'E1.4', 'name': 'Identity Provider Compromise', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 4, 'risk_score': 8, 'risk_level': 'Medium'},
                {'id': 'E1.5', 'name': 'API Key Exposure', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High'},
            ],
            'mitigations': [
                {'threat_id': 'E1.1', 'type': 'Preventive', 'control': 'PCI DSS compliance, tokenization, encryption'},
                {'threat_id': 'E1.1', 'type': 'Detective', 'control': 'Compliance monitoring, audit logging'},
                {'threat_id': 'E1.1', 'type': 'Responsive', 'control': 'Incident response, regulatory reporting'},
                {'threat_id': 'E1.5', 'type': 'Preventive', 'control': 'API key rotation, secure storage, least privilege'},
                {'threat_id': 'E1.5', 'type': 'Detective', 'control': 'API usage monitoring, anomaly detection'},
                {'threat_id': 'E1.5', 'type': 'Responsive', 'control': 'Key revocation, access review'},
            ]
        }
    }
    return threats_data

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🏦 SecureBank Threat Model Dashboard</h1>
        <p>Comprehensive Trust Boundary Analysis with Threats, Risks & Mitigations</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Load data
    threat_data = load_threat_data()
    
    # Sidebar for navigation
    st.sidebar.title("🔍 Navigation")
    view_mode = st.sidebar.selectbox(
        "Select View Mode",
        ["Overview Dashboard", "Trust Boundaries", "Threat Analysis", "Risk Assessment", "Mitigation Strategies", "STRIDE Analysis"]
    )
    
    # Risk filter
    st.sidebar.subheader("🎯 Risk Filter")
    risk_filter = st.sidebar.multiselect(
        "Filter by Risk Level",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )
    
    if view_mode == "Overview Dashboard":
        display_overview_dashboard(threat_data, risk_filter)
    elif view_mode == "Trust Boundaries":
        display_trust_boundaries(threat_data, risk_filter)
    elif view_mode == "Threat Analysis":
        display_threat_analysis(threat_data, risk_filter)
    elif view_mode == "Risk Assessment":
        display_risk_assessment(threat_data, risk_filter)
    elif view_mode == "Mitigation Strategies":
        display_mitigation_strategies(threat_data, risk_filter)
    elif view_mode == "STRIDE Analysis":
        display_stride_analysis(threat_data, risk_filter)

def display_overview_dashboard(threat_data, risk_filter):
    st.header("📊 Overview Dashboard")
    
    # Collect all threats for metrics
    all_threats = []
    for boundary, data in threat_data.items():
        for threat in data['threats']:
            if threat['risk_level'] in risk_filter:
                all_threats.append({**threat, 'boundary': boundary})
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Threats", len(all_threats))
    
    with col2:
        critical_threats = len([t for t in all_threats if t['risk_level'] == 'Critical'])
        st.metric("Critical Threats", critical_threats)
    
    with col3:
        avg_risk = np.mean([t['risk_score'] for t in all_threats]) if all_threats else 0
        st.metric("Average Risk Score", f"{avg_risk:.1f}")
    
    with col4:
        boundaries_count = len(threat_data)
        st.metric("Trust Boundaries", boundaries_count)
    
    # Risk distribution chart
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Risk Distribution by Level")
        risk_counts = {}
        for threat in all_threats:
            risk_level = threat['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        if risk_counts:
            fig = px.pie(
                values=list(risk_counts.values()),
                names=list(risk_counts.keys()),
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Threats by Trust Boundary")
        boundary_counts = {}
        for threat in all_threats:
            boundary = threat['boundary']
            boundary_counts[boundary] = boundary_counts.get(boundary, 0) + 1
        
        if boundary_counts:
            fig = px.bar(
                x=list(boundary_counts.keys()),
                y=list(boundary_counts.values()),
                labels={'x': 'Trust Boundary', 'y': 'Number of Threats'}
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
    # Risk heatmap
    st.subheader("Risk Heatmap by STRIDE Category")
    
    # Create STRIDE vs Boundary matrix
    stride_categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege']
    boundaries = list(threat_data.keys())
    
    matrix_data = []
    for boundary in boundaries:
        row = []
        for category in stride_categories:
            threats_in_category = [t for t in threat_data[boundary]['threats'] 
                                   if t['category'] == category and t['risk_level'] in risk_filter]
            avg_risk = np.mean([t['risk_score'] for t in threats_in_category]) if threats_in_category else 0
            row.append(avg_risk)
        matrix_data.append(row)
    
    fig = go.Figure(data=go.Heatmap(
        z=matrix_data,
        x=stride_categories,
        y=boundaries,
        colorscale='RdYlBu_r',
        text=[[f"{val:.1f}" for val in row] for row in matrix_data],
        texttemplate="%{text}",
        textfont={"size": 10},
    ))
    fig.update_layout(
        title="Average Risk Score by STRIDE Category and Trust Boundary",
        xaxis_title="STRIDE Category",
        yaxis_title="Trust Boundary"
    )
    st.plotly_chart(fig, use_container_width=True)

def display_trust_boundaries(threat_data, risk_filter):
    st.header("🔒 Trust Boundaries Analysis")
    
    # Trust boundary selector
    boundary_names = list(threat_data.keys())
    selected_boundary = st.selectbox("Select Trust Boundary", boundary_names)
    
    boundary_data = threat_data[selected_boundary]
    
    # Boundary info
    st.markdown(f"""
    <div class="boundary-card">
        <h3>{selected_boundary}</h3>
        <p><strong>Description:</strong> {boundary_data['description']}</p>
        <p><strong>Components:</strong> {', '.join(boundary_data['components'])}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Filter threats by risk level
    filtered_threats = [t for t in boundary_data['threats'] if t['risk_level'] in risk_filter]
    
    # Threats table
    st.subheader("🎯 Threats in this Boundary")
    if filtered_threats:
        df_threats = pd.DataFrame(filtered_threats)
        
        # Style the dataframe
        def style_risk_level(val):
            if val == 'Critical':
                return 'background-color: #dc3545; color: white'
            elif val == 'High':
                return 'background-color: #fd7e14; color: white'
            elif val == 'Medium':
                return 'background-color: #ffc107; color: black'
            elif val == 'Low':
                return 'background-color: #28a745; color: white'
            return ''
        
        styled_df = df_threats[['id', 'name', 'category', 'risk_level', 'risk_score', 'likelihood', 'impact']].style.applymap(
            style_risk_level, subset=['risk_level']
        )
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("No threats found for the selected risk filter.")
    
    # Risk visualization for this boundary
    col1, col2 = st.columns(2)
    
    with col1:
        if filtered_threats:
            # Risk score distribution
            fig = px.histogram(
                df_threats,
                x='risk_score',
                nbins=10,
                title=f"Risk Score Distribution - {selected_boundary}",
                labels={'risk_score': 'Risk Score', 'count': 'Number of Threats'}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if filtered_threats:
            # STRIDE category distribution
            fig = px.bar(
                df_threats['category'].value_counts().reset_index(),
                x='index',
                y='category',
                title=f"Threats by STRIDE Category - {selected_boundary}",
                labels={'index': 'STRIDE Category', 'category': 'Number of Threats'}
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

def display_threat_analysis(threat_data, risk_filter):
    st.header("🎯 Detailed Threat Analysis")
    
    # Collect all threats
    all_threats = []
    for boundary, data in threat_data.items():
        for threat in data['threats']:
            if threat['risk_level'] in risk_filter:
                all_threats.append({**threat, 'boundary': boundary})
    
    if not all_threats:
        st.warning("No threats found for the selected risk filter.")
        return
    
    # Threat search
    search_term = st.text_input("🔍 Search threats by name or ID:")
    if search_term:
        all_threats = [t for t in all_threats if search_term.lower() in t['name'].lower() or search_term.lower() in t['id'].lower()]
    
    # Sort options
    sort_by = st.selectbox("Sort by:", ["Risk Score", "Likelihood", "Impact", "Name"])
    if sort_by == "Risk Score":
        all_threats.sort(key=lambda x: x['risk_score'], reverse=True)
    elif sort_by == "Likelihood":
        all_threats.sort(key=lambda x: x['likelihood'], reverse=True)
    elif sort_by == "Impact":
        all_threats.sort(key=lambda x: x['impact'], reverse=True)
    elif sort_by == "Name":
        all_threats.sort(key=lambda x: x['name'])
    
    # Display threats
    for threat in all_threats:
        with st.expander(f"🎯 {threat['id']}: {threat['name']} (Risk: {threat['risk_score']})"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Boundary:** {threat['boundary']}")
                st.write(f"**Category:** {threat['category']}")
                st.write(f"**Likelihood:** {threat['likelihood']}")
                st.write(f"**Impact:** {threat['impact']}")
                st.markdown(f"**Risk Level:** <span class='risk-{threat['risk_level'].lower()}'>{threat['risk_level']}</span>", unsafe_allow_html=True)
            with col2:
                st.subheader("Associated Mitigations:")
                threat_mitigations = [m for boundary_name, boundary_data in threat_data.items() for m in boundary_data['mitigations'] if m['threat_id'] == threat['id']]
                if threat_mitigations:
                    for mitigation in threat_mitigations:
                        st.markdown(f"""
                        <div class="mitigation-item">
                            <strong>{mitigation['type']}:</strong> {mitigation['control']}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("No specific mitigations found for this threat.")
            st.markdown("---")

def display_risk_assessment(threat_data, risk_filter):
    st.header("📈 Risk Assessment Overview")
    
    all_threats = []
    for boundary, data in threat_data.items():
        for threat in data['threats']:
            if threat['risk_level'] in risk_filter:
                all_threats.append({**threat, 'boundary': boundary})
    
    if not all_threats:
        st.warning("No threats found for the selected risk filter.")
        return
    
    df_risks = pd.DataFrame(all_threats)
    
    st.subheader("Risk Matrix (Likelihood vs. Impact)")
    
    # Create the risk matrix
    risk_matrix_data = pd.pivot_table(df_risks, values='risk_score', index='impact', columns='likelihood', aggfunc='mean').fillna(0)
    
    fig = go.Figure(data=go.Heatmap(
        z=risk_matrix_data.values,
        x=risk_matrix_data.columns.tolist(),
        y=risk_matrix_data.index.tolist(),
        colorscale='RdYlGn_r',
        text=[[f"{val:.1f}" for val in row] for row in risk_matrix_data.values],
        texttemplate="%{text}",
        textfont={"size": 10},
    ))
    fig.update_layout(
        title="Average Risk Score",
        xaxis_title="Likelihood (1-5)",
        yaxis_title="Impact (1-5)",
        xaxis=dict(tickmode='array', tickvals=list(range(1,6))),
        yaxis=dict(tickmode='array', tickvals=list(range(1,6)))
    )
    st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Top Riskiest Threats")
    top_n = st.slider("Show Top N Threats:", 5, len(all_threats), 10)
    
    sorted_threats = sorted(all_threats, key=lambda x: x['risk_score'], reverse=True)[:top_n]
    
    if sorted_threats:
        df_top_risks = pd.DataFrame(sorted_threats)
        def style_risk_level(val):
            if val == 'Critical':
                return 'background-color: #dc3545; color: white'
            elif val == 'High':
                return 'background-color: #fd7e14; color: white'
            elif val == 'Medium':
                return 'background-color: #ffc107; color: black'
            elif val == 'Low':
                return 'background-color: #28a745; color: white'
            return ''
        
        styled_df = df_top_risks[['id', 'name', 'boundary', 'category', 'risk_level', 'risk_score', 'likelihood', 'impact']].style.applymap(
            style_risk_level, subset=['risk_level']
        )
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("No threats to display for the top risks.")

def display_mitigation_strategies(threat_data, risk_filter):
    st.header("🛡️ Mitigation Strategies")
    
    all_mitigations = []
    all_threats_flat = []
    for boundary, data in threat_data.items():
        for threat in data['threats']:
            if threat['risk_level'] in risk_filter:
                all_threats_flat.append(threat)
                
        for mitigation in data['mitigations']:
            # Only include mitigations for threats that pass the risk filter
            associated_threat = next((t for t in data['threats'] if t['id'] == mitigation['threat_id'] and t['risk_level'] in risk_filter), None)
            if associated_threat:
                all_mitigations.append({**mitigation, 'boundary': boundary, 'threat_name': associated_threat['name'], 'threat_risk_level': associated_threat['risk_level']})
    
    if not all_mitigations:
        st.warning("No mitigations found for the selected risk filter.")
        return
    
    # Filter and sort mitigations
    st.subheader("Mitigations by Type")
    mitigation_type_filter = st.multiselect(
        "Filter by Mitigation Type",
        ["Preventive", "Detective", "Responsive"],
        default=["Preventive", "Detective", "Responsive"]
    )
    
    filtered_mitigations = [m for m in all_mitigations if m['type'] in mitigation_type_filter]
    
    if filtered_mitigations:
        for boundary in sorted(list(set([m['boundary'] for m in filtered_mitigations]))):
            st.subheader(f"Boundary: {boundary}")
            boundary_mitigations = [m for m in filtered_mitigations if m['boundary'] == boundary]
            
            for mitigation_type in ["Preventive", "Detective", "Responsive"]:
                type_mitigations = [m for m in boundary_mitigations if m['type'] == mitigation_type]
                if type_mitigations:
                    st.markdown(f"**{mitigation_type} Controls:**")
                    for mit in type_mitigations:
                        st.markdown(f"""
                        <div class="mitigation-item">
                            <strong>Threat:</strong> {mit['threat_name']} (<span class='risk-{mit['threat_risk_level'].lower()}'>{mit['threat_risk_level']}</span>) <br>
                            <strong>Control:</strong> {mit['control']}
                        </div>
                        """, unsafe_allow_html=True)
    else:
        st.info("No mitigations match the selected filters.")
        
    st.markdown("---")
    
    st.subheader("Mitigation Effectiveness Visualization")
    
    # Calculate average risk score per mitigation type (before/after mitigation)
    # This is a simplified representation. A real effectiveness would require more data.
    mitigation_effectiveness = {}
    for threat in all_threats_flat:
        threat_id = threat['id']
        risk_score = threat['risk_score']
        
        related_mitigations = [m for boundary_name, boundary_data in threat_data.items() for m in boundary_data['mitigations'] if m['threat_id'] == threat_id]
        
        if related_mitigations:
            for mit in related_mitigations:
                mitigation_type = mit['type']
                if mitigation_type not in mitigation_effectiveness:
                    mitigation_effectiveness[mitigation_type] = {'total_risk_reduced': 0, 'count': 0}
                
                # Assume a fixed reduction for demonstration, or calculate based on 'control' keywords
                reduction = 0
                if "encryption" in mit['control'].lower() or "segmentation" in mit['control'].lower() or "validation" in mit['control'].lower():
                    reduction = risk_score * 0.4 # Significant reduction
                elif "monitoring" in mit['control'].lower() or "detection" in mit['control'].lower():
                    reduction = risk_score * 0.2 # Moderate reduction
                else:
                    reduction = risk_score * 0.1 # Minor reduction
                
                mitigation_effectiveness[mitigation_type]['total_risk_reduced'] += reduction
                mitigation_effectiveness[mitigation_type]['count'] += 1
    
    if mitigation_effectiveness:
        mitigation_df = pd.DataFrame([
            {'Type': k, 'Average Risk Reduction': v['total_risk_reduced'] / v['count']}
            for k, v in mitigation_effectiveness.items() if v['count'] > 0
        ])
        
        fig = px.bar(
            mitigation_df,
            x='Type',
            y='Average Risk Reduction',
            title='Average Risk Reduction by Mitigation Type (Simulated)',
            labels={'Average Risk Reduction': 'Average Risk Score Reduction'},
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Cannot generate mitigation effectiveness chart without relevant data.")

def display_stride_analysis(threat_data, risk_filter):
    st.header("📊 STRIDE Analysis")
    
    all_threats = []
    for boundary, data in threat_data.items():
        for threat in data['threats']:
            if threat['risk_level'] in risk_filter:
                all_threats.append({**threat, 'boundary': boundary})
    
    if not all_threats:
        st.warning("No threats found for the selected risk filter.")
        return
    
    df_stride = pd.DataFrame(all_threats)
    
    # Overall STRIDE distribution
    st.subheader("Overall Threat Distribution by STRIDE Category")
    stride_counts = df_stride['category'].value_counts().reset_index()
    stride_counts.columns = ['Category', 'Count']
    
    fig = px.pie(
        stride_counts,
        values='Count',
        names='Category',
        title="Distribution of Threats Across STRIDE Categories",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # STRIDE by Trust Boundary
    st.subheader("STRIDE Categories per Trust Boundary")
    
    for boundary_name, boundary_data in threat_data.items():
        st.markdown(f"""
        <div class="stride-category">
            <h3>{boundary_name}</h3>
        </div>
        """, unsafe_allow_html=True)
        
        boundary_threats = [t for t in boundary_data['threats'] if t['risk_level'] in risk_filter]
        if boundary_threats:
            df_boundary_threats = pd.DataFrame(boundary_threats)
            stride_counts_boundary = df_boundary_threats['category'].value_counts().reset_index()
            stride_counts_boundary.columns = ['Category', 'Count']
            
            fig = px.bar(
                stride_counts_boundary,
                x='Category',
                y='Count',
                title=f"STRIDE Distribution for {boundary_name}",
                labels={'Category': 'STRIDE Category', 'Count': 'Number of Threats'},
                color='Category',
                color_discrete_map={
                    'Spoofing': '#667eea',
                    'Tampering': '#ff6b6b',
                    'Repudiation': '#fd7e14',
                    'Information Disclosure': '#20c997',
                    'Denial of Service': '#6f42c1',
                    'Elevation of Privilege': '#007bff'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info(f"No threats in '{boundary_name}' for the selected risk filter to display STRIDE analysis.")
        st.markdown("---")

if __name__ == "__main__":
    main()