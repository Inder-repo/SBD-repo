import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
import uuid # For generating unique IDs for new entries

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

# Helper function to calculate risk level
def calculate_risk(likelihood, impact):
    risk_score = likelihood * impact
    if risk_score >= 15:
        risk_level = 'Critical'
    elif risk_score >= 10:
        risk_level = 'High'
    elif risk_score >= 5:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    return risk_score, risk_level

# Initial data structure for the threat model (default or loaded from session state)
def get_initial_threat_data():
    return {
        'Boundary 1: Internet → DMZ': {
            'description': 'Zero Trust Zone - External users accessing web-facing components',
            'components': ['Internet Users', 'Web Application Firewall', 'Load Balancer'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Phishing Attacks', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Extended Validation SSL certificates with clear visual indicators'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Certificate transparency logs and brand monitoring services'},
                     {'id': str(uuid.uuid4()), 'type': 'Responsive', 'control': 'Rapid takedown procedures and customer notifications'}
                 ]},
                {'id': str(uuid.uuid4()), 'name': 'SQL Injection', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Parameterized queries, input validation, WAF rules'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Database query monitoring, anomaly detection'},
                     {'id': str(uuid.uuid4()), 'type': 'Responsive', 'control': 'Automatic account suspension, query blocking'}
                 ]},
            ]
        },
        'Boundary 2: DMZ → Internal': {
            'description': 'Web tier to Application tier - Authenticated requests only',
            'components': ['Web Servers (DMZ)', 'Application Servers', 'Authentication Services'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Lateral Movement', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Network segmentation, micro-segmentation, zero-trust architecture'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Network traffic analysis, behavioral monitoring'}
                 ]},
            ]
        },
    }

# Initialize session state for threat data
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = get_initial_threat_data()

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🏦 SecureBank Threat Model Dashboard</h1>
        <p>Comprehensive Trust Boundary Analysis with Threats, Risks & Mitigations</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("🔍 Navigation")
    view_mode = st.sidebar.selectbox(
        "Select View Mode",
        ["Overview Dashboard", "Trust Boundaries", "Threat Analysis", "Risk Assessment", "Mitigation Strategies", "STRIDE Analysis", "Manage Threat Model"]
    )
    
    # Risk filter
    st.sidebar.subheader("🎯 Risk Filter")
    risk_filter = st.sidebar.multiselect(
        "Filter by Risk Level",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )

    # Reset button
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Reset Threat Model"):
        st.session_state.threat_model = get_initial_threat_data()
        st.rerun()
        st.success("Threat model reset to default data!")
    
    if view_mode == "Overview Dashboard":
        display_overview_dashboard(st.session_state.threat_model, risk_filter)
    elif view_mode == "Trust Boundaries":
        display_trust_boundaries(st.session_state.threat_model, risk_filter)
    elif view_mode == "Threat Analysis":
        display_threat_analysis(st.session_state.threat_model, risk_filter)
    elif view_mode == "Risk Assessment":
        display_risk_assessment(st.session_state.threat_model, risk_filter)
    elif view_mode == "Mitigation Strategies":
        display_mitigation_strategies(st.session_state.threat_model, risk_filter)
    elif view_mode == "STRIDE Analysis":
        display_stride_analysis(st.session_state.threat_model, risk_filter)
    elif view_mode == "Manage Threat Model":
        manage_threat_model()

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
        else:
            st.info("No threats to display for risk distribution.")
    
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
        else:
            st.info("No threats to display for trust boundary distribution.")
    
    # Risk heatmap
    st.subheader("Risk Heatmap by STRIDE Category")
    
    # Create STRIDE vs Boundary matrix
    stride_categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege']
    boundaries = list(threat_data.keys())
    
    if boundaries:
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
    else:
        st.info("No trust boundaries defined to generate the risk heatmap.")

def display_trust_boundaries(threat_data, risk_filter):
    st.header("🔒 Trust Boundaries Analysis")
    
    boundary_names = list(threat_data.keys())
    if not boundary_names:
        st.warning("No trust boundaries defined. Please go to 'Manage Threat Model' to add some.")
        return

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
        st.info("No threats found for the selected risk filter in this boundary.")
    
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
        else:
            st.info("No threats to display risk score distribution.")
    
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
        else:
            st.info("No threats to display STRIDE category distribution.")

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
                if threat['mitigations']:
                    for mitigation in threat['mitigations']:
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
    # Ensure all likelihood and impact values from 1 to 5 are present for consistent matrix
    likelihood_values = sorted(list(set(df_risks['likelihood'].tolist() + list(range(1, 6)))))
    impact_values = sorted(list(set(df_risks['impact'].tolist() + list(range(1, 6)))))

    risk_matrix_data = pd.pivot_table(df_risks, values='risk_score', index='impact', columns='likelihood', aggfunc='mean').fillna(0)
    
    # Reindex to ensure all 1-5 values are present, filling with 0 if no data
    risk_matrix_data = risk_matrix_data.reindex(index=impact_values, columns=likelihood_values, fill_value=0)

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
    top_n = st.slider("Show Top N Threats:", 5, len(all_threats), min(10, len(all_threats)))
    
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
                for mitigation in threat['mitigations']:
                    all_mitigations.append({
                        **mitigation,
                        'boundary': boundary,
                        'threat_name': threat['name'],
                        'threat_id': threat['id'],
                        'threat_risk_level': threat['risk_level']
                    })
    
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
    
    # Calculate average risk score per mitigation type (simplified simulation)
    mitigation_effectiveness = {}
    for threat in all_threats_flat:
        risk_score = threat['risk_score']
        
        # Consider only mitigations that are part of the filtered set
        related_mitigations = [m for m in threat['mitigations'] if m['type'] in mitigation_type_filter]
        
        if related_mitigations:
            for mit in related_mitigations:
                mitigation_type = mit['type']
                if mitigation_type not in mitigation_effectiveness:
                    mitigation_effectiveness[mitigation_type] = {'total_risk_reduced': 0, 'count': 0}
                
                # Assume a fixed reduction for demonstration, or calculate based on 'control' keywords
                reduction = 0
                if "encryption" in mit['control'].lower() or "segmentation" in mit['control'].lower() or "validation" in mit['control'].lower() or "waf" in mit['control'].lower() or "hsm" in mit['control'].lower():
                    reduction = risk_score * 0.4 # Significant reduction
                elif "monitoring" in mit['control'].lower() or "detection" in mit['control'].lower() or "audit" in mit['control'].lower():
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
    
    boundary_names = list(threat_data.keys())
    if not boundary_names:
        st.info("No trust boundaries defined to perform STRIDE analysis.")
        return

    for boundary_name in boundary_names:
        st.markdown(f"""
        <div class="stride-category">
            <h3>{boundary_name}</h3>
        </div>
        """, unsafe_allow_html=True)
        
        boundary_threats = [t for t in threat_data[boundary_name]['threats'] if t['risk_level'] in risk_filter]
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

def manage_threat_model():
    st.header("🛠️ Manage Threat Model")
    st.write("Here you can add, edit, and delete trust boundaries, threats, and mitigations.")

    # --- Manage Trust Boundaries ---
    st.subheader("Manage Trust Boundaries")
    
    boundary_names = list(st.session_state.threat_model.keys())
    
    # Add New Boundary
    with st.expander("➕ Add New Trust Boundary"):
        with st.form("add_boundary_form", clear_on_submit=True):
            new_boundary_name = st.text_input("Boundary Name", key="new_boundary_name_input")
            new_boundary_description = st.text_area("Description", key="new_boundary_desc_input")
            new_boundary_components = st.text_input("Components (comma-separated)", key="new_boundary_comp_input")
            
            if st.form_submit_button("Add Boundary"):
                if new_boundary_name and new_boundary_name not in st.session_state.threat_model:
                    st.session_state.threat_model[new_boundary_name] = {
                        'description': new_boundary_description,
                        'components': [c.strip() for c in new_boundary_components.split(',') if c.strip()],
                        'threats': []
                    }
                    st.success(f"Trust Boundary '{new_boundary_name}' added!")
                    st.rerun()
                elif new_boundary_name:
                    st.warning(f"Trust Boundary '{new_boundary_name}' already exists.")
                else:
                    st.error("Boundary Name cannot be empty.")

    if not boundary_names:
        st.info("No trust boundaries defined. Add one above to get started.")
        return

    selected_boundary_to_manage = st.selectbox("Select Boundary to Manage", boundary_names, key="select_boundary_to_manage")

    boundary_data = st.session_state.threat_model[selected_boundary_to_manage]

    # Edit/Delete Boundary
    st.markdown(f"#### Details for: {selected_boundary_to_manage}")
    st.write(f"**Description:** {boundary_data['description']}")
    st.write(f"**Components:** {', '.join(boundary_data['components'])}")

    col_edit_del_boundary = st.columns(2)
    with col_edit_del_boundary[0]:
        with st.expander(f"✏️ Edit '{selected_boundary_to_manage}'"):
            with st.form(f"edit_boundary_form_{selected_boundary_to_manage}", clear_on_submit=False):
                edited_description = st.text_area("Description", value=boundary_data['description'], key=f"edit_desc_{selected_boundary_to_manage}")
                edited_components = st.text_input("Components (comma-separated)", value=", ".join(boundary_data['components']), key=f"edit_comp_{selected_boundary_to_manage}")
                
                if st.form_submit_button("Save Changes"):
                    st.session_state.threat_model[selected_boundary_to_manage]['description'] = edited_description
                    st.session_state.threat_model[selected_boundary_to_manage]['components'] = [c.strip() for c in edited_components.split(',') if c.strip()]
                    st.success(f"Boundary '{selected_boundary_to_manage}' updated!")
                    st.rerun()
    with col_edit_del_boundary[1]:
        if st.button(f"🗑️ Delete '{selected_boundary_to_manage}'", key=f"delete_boundary_{selected_boundary_to_manage}"):
            del st.session_state.threat_model[selected_boundary_to_manage]
            st.success(f"Boundary '{selected_boundary_to_manage}' deleted!")
            st.rerun()
    
    st.markdown("---")

    # --- Manage Threats within selected Boundary ---
    st.subheader(f"Manage Threats in '{selected_boundary_to_manage}'")

    # Add New Threat
    with st.expander(f"➕ Add New Threat to '{selected_boundary_to_manage}'"):
        with st.form(f"add_threat_form_{selected_boundary_to_manage}", clear_on_submit=True):
            threat_name = st.text_input("Threat Name", key=f"new_threat_name_{selected_boundary_to_manage}")
            threat_category = st.selectbox("STRIDE Category", ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'], key=f"new_threat_cat_{selected_boundary_to_manage}")
            threat_likelihood = st.slider("Likelihood (1-5)", 1, 5, 3, key=f"new_threat_lik_{selected_boundary_to_manage}")
            threat_impact = st.slider("Impact (1-5)", 1, 5, 3, key=f"new_threat_imp_{selected_boundary_to_manage}")
            
            if st.form_submit_button("Add Threat"):
                if threat_name:
                    risk_score, risk_level = calculate_risk(threat_likelihood, threat_impact)
                    new_threat_id = f"T{len(boundary_data['threats']) + 1}.{str(uuid.uuid4())[:4]}" # Simple ID generation
                    st.session_state.threat_model[selected_boundary_to_manage]['threats'].append({
                        'id': new_threat_id,
                        'name': threat_name,
                        'category': threat_category,
                        'likelihood': threat_likelihood,
                        'impact': threat_impact,
                        'risk_score': risk_score,
                        'risk_level': risk_level,
                        'mitigations': [] # Initialize with empty mitigations
                    })
                    st.success(f"Threat '{threat_name}' added to '{selected_boundary_to_manage}'!")
                    st.rerun()
                else:
                    st.error("Threat Name cannot be empty.")

    # List and Manage Existing Threats
    if boundary_data['threats']:
        for i, threat in enumerate(boundary_data['threats']):
            with st.expander(f"🎯 {threat['id']}: {threat['name']} (Risk: {threat['risk_score']}, {threat['risk_level']})"):
                st.write(f"**Category:** {threat['category']}")
                st.write(f"**Likelihood:** {threat['likelihood']}")
                st.write(f"**Impact:** {threat['impact']}")
                st.markdown(f"**Risk Level:** <span class='risk-{threat['risk_level'].lower()}'>{threat['risk_level']}</span>", unsafe_allow_html=True)

                col_edit_del_threat = st.columns(2)
                with col_edit_del_threat[0]:
                    with st.expander(f"✏️ Edit Threat '{threat['name']}'"):
                        with st.form(f"edit_threat_form_{threat['id']}", clear_on_submit=False):
                            edited_threat_name = st.text_input("Threat Name", value=threat['name'], key=f"edit_threat_name_{threat['id']}")
                            edited_threat_category = st.selectbox("STRIDE Category", ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'], index=['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'].index(threat['category']), key=f"edit_threat_cat_{threat['id']}")
                            edited_threat_likelihood = st.slider("Likelihood (1-5)", 1, 5, threat['likelihood'], key=f"edit_threat_lik_{threat['id']}")
                            edited_threat_impact = st.slider("Impact (1-5)", 1, 5, threat['impact'], key=f"edit_threat_imp_{threat['id']}")
                            
                            if st.form_submit_button("Save Threat Changes"):
                                risk_score, risk_level = calculate_risk(edited_threat_likelihood, edited_threat_impact)
                                st.session_state.threat_model[selected_boundary_to_manage]['threats'][i].update({
                                    'name': edited_threat_name,
                                    'category': edited_threat_category,
                                    'likelihood': edited_threat_likelihood,
                                    'impact': edited_threat_impact,
                                    'risk_score': risk_score,
                                    'risk_level': risk_level
                                })
                                st.success(f"Threat '{edited_threat_name}' updated!")
                                st.rerun()
                with col_edit_del_threat[1]:
                    if st.button(f"🗑️ Delete Threat '{threat['name']}'", key=f"delete_threat_{threat['id']}"):
                        st.session_state.threat_model[selected_boundary_to_manage]['threats'].pop(i)
                        st.success(f"Threat '{threat['name']}' deleted!")
                        st.rerun()
                
                st.markdown("---")
                
                # --- Manage Mitigations for this Threat ---
                st.markdown(f"##### Mitigations for '{threat['name']}'")
                
                # Add New Mitigation
                with st.expander(f"➕ Add New Mitigation for '{threat['name']}'"):
                    with st.form(f"add_mitigation_form_{threat['id']}", clear_on_submit=True):
                        mitigation_type = st.selectbox("Mitigation Type", ["Preventive", "Detective", "Responsive"], key=f"new_mit_type_{threat['id']}")
                        mitigation_control = st.text_area("Control Description", key=f"new_mit_control_{threat['id']}")
                        
                        if st.form_submit_button("Add Mitigation"):
                            if mitigation_control:
                                new_mitigation_id = str(uuid.uuid4())
                                st.session_state.threat_model[selected_boundary_to_manage]['threats'][i]['mitigations'].append({
                                    'id': new_mitigation_id,
                                    'type': mitigation_type,
                                    'control': mitigation_control
                                })
                                st.success(f"Mitigation added for '{threat['name']}'!")
                                st.rerun()
                            else:
                                st.error("Control Description cannot be empty.")
                
                # List and Manage Existing Mitigations
                if threat['mitigations']:
                    for j, mitigation in enumerate(threat['mitigations']):
                        with st.expander(f"🛡️ {mitigation['type']}: {mitigation['control'][:50]}..."):
                            st.write(f"**Type:** {mitigation['type']}")
                            st.write(f"**Control:** {mitigation['control']}")
                            
                            col_edit_del_mit = st.columns(2)
                            with col_edit_del_mit[0]:
                                with st.expander(f"✏️ Edit Mitigation '{mitigation['id']}'"):
                                    with st.form(f"edit_mitigation_form_{mitigation['id']}", clear_on_submit=False):
                                        edited_mitigation_type = st.selectbox("Mitigation Type", ["Preventive", "Detective", "Responsive"], index=["Preventive", "Detective", "Responsive"].index(mitigation['type']), key=f"edit_mit_type_{mitigation['id']}")
                                        edited_mitigation_control = st.text_area("Control Description", value=mitigation['control'], key=f"edit_mit_control_{mitigation['id']}")
                                        
                                        if st.form_submit_button("Save Mitigation Changes"):
                                            st.session_state.threat_model[selected_boundary_to_manage]['threats'][i]['mitigations'][j].update({
                                                'type': edited_mitigation_type,
                                                'control': edited_mitigation_control
                                            })
                                            st.success("Mitigation updated!")
                                            st.rerun()
                            with col_edit_del_mit[1]:
                                if st.button(f"🗑️ Delete Mitigation '{mitigation['id']}'", key=f"delete_mitigation_{mitigation['id']}"):
                                    st.session_state.threat_model[selected_boundary_to_manage]['threats'][i]['mitigations'].pop(j)
                                    st.success("Mitigation deleted!")
                                    st.rerun()
                else:
                    st.info("No mitigations added for this threat yet.")
                st.markdown("---") # Separator for threats
    else:
        st.info(f"No threats defined for '{selected_boundary_to_manage}'. Add one above.")


if __name__ == "__main__":
    main()
