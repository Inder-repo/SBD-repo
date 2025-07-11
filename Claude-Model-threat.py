import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
import uuid # For generating unique IDs for new entries
import json # For passing data between Python and JavaScript
from datetime import datetime

# Firebase imports (will be loaded via script tags in the HTML part for the custom component)
# For Streamlit backend, we don't directly import Python Firebase SDK here,
# but we will manage data persistence using Firestore based on user actions.

# Page configuration
st.set_page_config(
    page_title="Threat Model",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    body {
        font-family: 'Inter', sans-serif;
    }

    .main-header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
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
        background: rgba(255, 255, 0.1);
        padding: 0.8rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        /* Corrected from 44px to 4px */
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

    /* Styles for Threat Analysis & Risk Assessment Cards */
    .threat-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
        gap: 25px;
        margin: 30px 0;
    }
    .threat-card {
        background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
        border-radius: 15px;
        padding: 25px;
        box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        border-left: 5px solid;
        transition: transform 0.3s ease;
    }
    .threat-card:hover {
        transform: translateY(-5px);
    }
    .threat-card.critical { border-left-color: #e74c3c; }
    .threat-card.high { border-left-color: #f39c12; }
    .threat-card.medium { border-left-color: #f1c40f; }
    .threat-card.low { border-left-color: #27ae60; }
    .threat-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
    }
    .threat-title {
        font-size: 1.3em;
        font-weight: 700;
        color: #2c3e50;
    }
    .risk-score-display { /* Renamed to avoid conflict with .risk-score */
        padding: 8px 12px;
        border-radius: 25px;
        font-weight: 700;
        font-size: 0.9em;
        color: white;
    }
    .risk-score-display.critical { background: #e74c3c; }
    .risk-score-display.high { background: #f39c12; }
    .risk-score-display.medium { background: #f1c40f; color: black; }
    .risk-score-display.low { background: #27ae60; }
    .threat-content {
        line-height: 1.6;
    }
    .threat-section-card { /* Renamed to avoid conflict with .threat-section */
        margin-bottom: 15px;
    }
    .threat-section-card h4 {
        color: #34495e;
        margin-bottom: 8px;
        font-size: 1.1em;
    }
    .threat-section-card p {
        margin: 0;
        color: #666;
    }
    .mitigation-list {
        background: #e8f5e8;
        padding: 15px;
        border-radius: 8px;
        margin-top: 10px;
    }
    .mitigation-list ul {
        margin: 0;
        padding-left: 20px;
    }
    .mitigation-list li {
        margin: 5px 0;
        color: #2d5a2d;
    }

    /* Diagram specific styles */
    #diagram-container {
        border: 1px solid #ddd;
        border-radius: 10px;
        background-color: #f9f9f9;
        overflow: hidden;
        position: relative;
        height: 550px; /* Adjusted height to fit within Streamlit */
        width: 100%;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    }
    #diagram-svg {
        width: 100%;
        height: 100%;
    }
    .diagram-node-rect { /* Changed from .diagram-node */
        cursor: grab; /* Indicate draggable */
        stroke: #333;
        stroke-width: 2px;
        transition: all 0.2s ease-in-out;
        filter: drop-shadow(2px 2px 4px rgba(0,0,0,0.1)); /* Drop shadow */
    }
    .diagram-node-rect:hover {
        transform: translateY(-3px);
        stroke: #2a5298;
        filter: drop-shadow(3px 3px 6px rgba(0,0,0,0.2));
    }
    .diagram-node-rect.selected {
        stroke: #667eea;
        stroke-width: 4px;
        filter: drop-shadow(4px 4px 8px rgba(0,0,0,0.3));
    }
    .diagram-node-text {
        font-family: 'Inter', sans-serif;
        font-size: 12px;
        fill: #333;
        pointer-events: none; /* Allows click to pass through to the rect */
        text-anchor: middle; /* Center text horizontally */
        dominant-baseline: central; /* Center text vertically */
        font-weight: 600;
    }
    .diagram-edge {
        stroke: #764ba2;
        stroke-width: 2px;
        fill: none;
        marker-end: url(#arrowhead);
    }
    .diagram-edge-label {
        font-family: 'Inter', sans-serif;
        font-size: 10px;
        fill: #555;
        background-color: rgba(255,255,255,0.9); /* More opaque background */
        padding: 3px 8px; /* Slightly larger padding */
        border-radius: 5px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        font-weight: 500;
    }
    .diagram-controls {
        position: absolute;
        top: 15px;
        left: 15px;
        z-index: 10;
        display: flex;
        flex-direction: column; /* Stack buttons vertically */
        gap: 10px;
    }
    .diagram-controls button {
        background-color: #007bff; /* Primary blue */
        color: white;
        border: none;
        padding: 10px 18px;
        border-radius: 8px; /* More rounded */
        cursor: pointer;
        font-size: 14px;
        font-weight: 600;
        transition: background-color 0.2s ease, transform 0.1s ease;
        box-shadow: 0 3px 8px rgba(0,123,255,0.3);
    }
    .diagram-controls button:hover {
        background-color: #0056b3; /* Darker blue on hover */
        transform: translateY(-1px);
    }
    .diagram-controls button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
        box-shadow: none;
    }
    .modal {
        display: none;
        position: fixed;
        z-index: 100;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        overflow: auto;
        background-color: rgba(0,0,0,0.6); /* Darker overlay */
        justify-content: center;
        align-items: center;
    }
    .modal-content {
        background-color: #fefefe;
        margin: auto;
        padding: 30px; /* Larger padding */
        border-radius: 15px; /* More rounded */
        width: 90%;
        max-width: 600px; /* Slightly wider */
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        display: flex;
        flex-direction: column;
        gap: 20px; /* Larger gap */
    }
    .modal-content h2 {
        color: #2a5298;
        margin-top: 0;
        font-size: 1.8em;
    }
    .modal-content label {
        font-weight: 600;
        color: #333;
        margin-bottom: 5px;
    }
    .modal-content input, .modal-content select, .modal-content textarea {
        width: calc(100% - 20px);
        padding: 12px; /* Larger input fields */
        margin-top: 5px;
        border: 1px solid #c0c0c0; /* Softer border */
        border-radius: 8px;
        font-size: 1em;
    }
    .modal-content textarea {
        min-height: 80px;
        resize: vertical;
    }
    .modal-content button {
        background-color: #28a745;
        color: white;
        padding: 12px 25px;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1.05em;
        font-weight: 600;
        transition: background-color 0.2s ease;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .modal-content button.cancel {
        background-color: #dc3545;
    }
    .modal-content button.cancel:hover {
        background-color: #c82333;
    }
    .modal-content button:hover {
        background-color: #218838;
    }

    /* Trust Boundary SVG styling */
    .trust-boundary-rect {
        fill: #e0f7fa; /* Light cyan */
        fill-opacity: 0.4;
        stroke: #007bff; /* Primary blue border */
        stroke-width: 2px;
        stroke-dasharray: 8 4; /* Dashed line */
        rx: 10; /* Rounded corners */
        ry: 10;
        pointer-events: none; /* Do not block clicks on elements inside */
    }
    .trust-boundary-label {
        font-family: 'Inter', sans-serif;
        font-size: 14px;
        fill: #0056b3; /* Darker blue text */
        font-weight: 700;
        pointer-events: none;
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

# Define a list of common trust boundaries that should always be available
COMMON_TRUST_BOUNDARIES = [
    "Internet -> DMZ",
    "DMZ -> Internal App Tier",
    "Internal App Tier -> Database",
    "Customer-Web App Boundary",
    "Web App-Payment Gateway Boundary",
    "Web App-Database Boundary",
    "Web App-Shipping Service Boundary",
    "User -> Application",
    "Application -> API Gateway",
    "API Gateway -> Microservice",
    "Microservice -> Database",
    "On-Premise -> Cloud",
    "External Partner Network"
]

# Define default mitigations for suggested threats
DEFAULT_MITIGATIONS = {
    'Phishing Attacks': [
        {'type': 'Preventive', 'control': 'Implement Multi-Factor Authentication (MFA)'},
        {'type': 'Preventive', 'control': 'Deploy strong email filtering and anti-phishing solutions'},
        {'type': 'Detective', 'control': 'Conduct regular security awareness training for users'}
    ],
    'DDoS Attacks': [
        {'type': 'Preventive', 'control': 'Utilize a DDoS protection service (e.g., Cloudflare, Akamai)'},
        {'type': 'Responsive', 'control': 'Implement traffic throttling and rate limiting'},
        {'type': 'Detective', 'control': 'Monitor network traffic for unusual spikes'}
    ],
    'SQL Injection': [
        {'type': 'Preventive', 'control': 'Use parameterized queries or prepared statements for all database interactions'},
        {'type': 'Preventive', 'control': 'Implement strict input validation and sanitization'},
        {'type': 'Preventive', 'control': 'Apply Principle of Least Privilege to database accounts'}
    ],
    'Cross-Site Scripting (XSS)': [
        {'type': 'Preventive', 'control': 'Sanitize all user-supplied input before rendering to HTML'},
        {'type': 'Preventive', 'control': 'Implement Content Security Policy (CSP)'},
        {'type': 'Preventive', 'control': 'Use output encoding for dynamic content'}
    ],
    'Database Injection': [ # Similar to SQL Injection but broader
        {'type': 'Preventive', 'control': 'Use ORMs or parameterized queries'},
        {'type': 'Preventive', 'control': 'Input validation and sanitization'},
        {'type': 'Preventive', 'control': 'Least privilege access to database'}
    ],
    'Data Exfiltration': [
        {'type': 'Preventive', 'control': 'Encrypt data at rest and in transit'},
        {'type': 'Detective', 'control': 'Implement Data Loss Prevention (DLP) solutions'},
        {'type': 'Detective', 'control': 'Monitor database activity for suspicious queries or large data transfers'}
    ],
    'Unauthorized Data Access': [
        {'type': 'Preventive', 'control': 'Implement strong access control policies (RBAC/ABAC)'},
        {'type': 'Preventive', 'control': 'Regularly review and revoke unnecessary access rights'},
        {'type': 'Detective', 'control': 'Audit logging of all data access attempts'}
    ],
    'Lateral Movement': [
        {'type': 'Preventive', 'control': 'Implement network segmentation and micro-segmentation'},
        {'type': 'Preventive', 'control': 'Restrict administrative access and use jump servers'},
        {'type': 'Detective', 'control': 'Monitor internal network traffic for anomalies'}
    ],
    'Internal Service Spoofing': [
        {'type': 'Preventive', 'control': 'Implement mutual TLS (mTLS) for service-to-service communication'},
        {'type': 'Preventive', 'control': 'Use strong authentication mechanisms between internal services'},
        {'type': 'Detective', 'control': 'Log and monitor service authentication failures'}
    ],
    'API Key Exposure': [
        {'type': 'Preventive', 'control': 'Store API keys securely (e.g., in a secrets manager)'},
        {'type': 'Preventive', 'control': 'Rotate API keys regularly'},
        {'type': 'Preventive', 'control': 'Implement API gateway policies for key validation and rate limiting'}
    ],
    'Data Sharing Violation': [
        {'type': 'Preventive', 'control': 'Define clear data sharing agreements and policies'},
        {'type': 'Preventive', 'control': 'Implement data masking or anonymization for sensitive data'},
        {'type': 'Detective', 'control': 'Audit and log all data transfers to external parties'}
    ],
    'Authentication Bypass': [
        {'type': 'Preventive', 'control': 'Enforce strong password policies and MFA'},
        {'type': 'Preventive', 'control': 'Implement robust session management'},
        {'type': 'Detective', 'control': 'Monitor authentication logs for brute-force or unusual login attempts'}
    ],
    'Credential Stuffing': [
        {'type': 'Preventive', 'control': 'Implement rate limiting on login attempts'},
        {'type': 'Preventive', 'control': 'Use CAPTCHA or reCAPTCHA'},
        {'type': 'Detective', 'control': 'Monitor for large numbers of failed login attempts from single IPs'}
    ],
    'Financial Fraud': [
        {'type': 'Preventive', 'control': 'Implement multi-factor authentication for high-value transactions'},
        {'type': 'Detective', 'control': 'Deploy real-time fraud detection systems'},
        {'type': 'Responsive', 'control': 'Establish clear incident response procedures for fraud alerts'}
    ],
    'Transaction Manipulation': [
        {'type': 'Preventive', 'control': 'Implement strong data integrity checks for all transactions'},
        {'type': 'Preventive', 'control': 'Use cryptographic signatures for transaction data'},
        {'type': 'Detective', 'control': 'Reconcile transactions regularly and detect discrepancies'}
    ],
    'Order Repudiation': [
        {'type': 'Preventive', 'control': 'Implement comprehensive audit logging for all order actions'},
        {'type': 'Preventive', 'control': 'Send email/SMS confirmations for critical order states'},
        {'type': 'Preventive', 'control': 'Require digital signatures for high-value orders'}
    ],
    'Payment Gateway Bypass': [
        {'type': 'Preventive', 'control': 'Server-side validation of all payment statuses and callbacks'},
        {'type': 'Preventive', 'control': 'Cryptographic signing and verification of payment gateway communications'},
        {'type': 'Detective', 'control': 'Monitor payment gateway logs for unauthorized access or unusual activity'}
    ]
}


# Initial data structure for the threat model (default or loaded from session state)
def get_initial_threat_data(sample_name="Banking Application"):
    if sample_name == "New Empty Model":
        # For a new empty model, initialize with an empty threat model
        # Common boundaries will be available in the dropdown but not pre-drawn or in threat_model
        return {}
    
    banking_threat_data = {
        # --- Banking Application Threats ---
        'Internet -> DMZ': {
            'description': 'External users accessing web-facing components of the banking application',
            'components': ['Internet Users', 'Web Application Firewall', 'Load Balancer'],
            'threats': [
                {'id': 'T_Bank_1', 'name': 'Phishing Attacks', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': 'M_Bank_1_1', 'type': 'Preventive', 'control': 'Extended Validation SSL certificates'},
                     {'id': 'M_Bank_1_2', 'type': 'Detective', 'control': 'Certificate transparency logs'}
                 ]},
                {'id': 'T_Bank_2', 'name': 'DDoS Attacks', 'category': 'Denial of Service', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_2_1', 'type': 'Preventive', 'control': 'DDoS Protection Service'},
                     {'id': 'M_Bank_2_2', 'type': 'Responsive', 'control': 'Traffic throttling'}
                 ]},
            ]
        },
        'DMZ -> Internal App Tier': {
            'description': 'Web tier to Application tier - Authenticated requests only for banking',
            'components': ['Web Servers (DMZ)', 'Application Servers', 'Authentication Services'],
            'threats': [
                {'id': 'T_Bank_3', 'name': 'SQL Injection', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_3_1', 'type': 'Preventive', 'control': 'Parameterized queries'},
                     {'id': 'M_Bank_3_2', 'type': 'Preventive', 'control': 'Input validation'}
                 ]},
                {'id': 'T_Bank_4', 'name': 'Lateral Movement', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_4_1', 'type': 'Preventive', 'control': 'Network segmentation'},
                     {'id': 'M_Bank_4_2', 'type': 'Detective', 'control': 'Network traffic analysis'}
                 ]},
            ]
        },
        'Internal App Tier -> Database': {
            'description': 'Application servers accessing database for banking',
            'components': ['Application Servers', 'Database Server'],
            'threats': [
                {'id': 'T_Bank_5', 'name': 'Data Exfiltration', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_5_1', 'type': 'Preventive', 'control': 'Data encryption at rest and in transit'},
                     {'id': 'M_Bank_5_2', 'type': 'Detective', 'control': 'Database activity monitoring'}
                 ]},
            ]
        },
    }
    order_processing_threat_data = {
        # --- Online Order Processing Threats ---
        'Customer-Web App Boundary': {
            'description': 'Customer interaction with the online order processing web application.',
            'components': ['Customer', 'Web Application'],
            'threats': [
                {'id': 'T_Order_1', 'name': 'Phishing Attack (Order System)', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': 'M_Order_1_1', 'type': 'Preventive', 'control': 'Multi-factor authentication (MFA) for login.'},
                     {'id': 'M_Order_1_2', 'type': 'Preventive', 'control': 'Strong email filtering and anti-phishing solutions.'}
                 ]},
                {'id': 'T_Order_2', 'name': 'DoS on Web Application (Order System)', 'category': 'Denial of Service', 'likelihood': 4, 'impact': 2, 'risk_score': 8, 'risk_level': 'Medium',
                 'mitigations': [
                     {'id': 'M_Order_2_1', 'type': 'Preventive', 'control': 'Implement rate limiting and anti-bot measures.'},
                     {'id': 'M_Order_2_2', 'type': 'Preventive', 'control': 'Use a CDN/DDoS protection service.'}
                 ]},
                {'id': 'T_Order_3', 'name': 'Order Repudiation', 'category': 'Repudiation', 'likelihood': 2, 'impact': 3, 'risk_score': 6, 'risk_level': 'Low',
                 'mitigations': [
                     {'id': 'M_Order_3_1', 'type': 'Preventive', 'control': 'Comprehensive audit logging of all order actions.'},
                     {'id': 'M_Order_3_2', 'type': 'Preventive', 'control': 'Email confirmations for order placement and shipment.'}
                 ]},
            ]
        },
        'Web App-Payment Gateway Boundary': {
            'description': 'Communication between the web application and the external payment gateway.',
            'components': ['Web Application', 'Payment Gateway'],
            'threats': [
                {'id': 'T_Order_4', 'name': 'Payment Gateway Bypass', 'category': 'Elevation of Privilege', 'likelihood': 3, 'impact': 3, 'risk_score': 9, 'risk_level': 'Medium',
                 'mitigations': [
                     {'id': 'M_Order_4_1', 'type': 'Preventive', 'control': 'Cryptographic signing/verification of payment callbacks.'},
                     {'id': 'M_Order_4_2', 'type': 'Preventive', 'control': 'Server-side validation of all payment statuses.'}
                 ]},
            ]
        },
        'Web App-Database Boundary': {
            'description': 'Communication between the web application and the order database.',
            'components': ['Web Application', 'Order Database'],
            'threats': [
                {'id': 'T_Order_5', 'name': 'SQL Injection (Order DB)', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Order_5_1', 'type': 'Preventive', 'control': 'Use parameterized queries/prepared statements.'},
                     {'id': 'M_Order_5_2', 'type': 'Preventive', 'control': 'Implement strict input validation and sanitization.'}
                 ]},
                {'id': 'T_Order_6', 'name': 'Data Exfiltration (Order DB)', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Order_6_1', 'type': 'Preventive', 'control': 'Data encryption at rest and in transit.'},
                     {'id': 'M_Order_6_2', 'type': 'Detective', 'control': 'Audit logging and anomaly detection on database access.'}
                 ]},
            ]
        },
        'Web App-Shipping Service Boundary': {
            'description': 'Communication between the web application and the shipping service.',
            'components': ['Web Application', 'Shipping Service'],
            'threats': [] # No specific threats for this boundary in the HTML sample, but it's defined.
        }
    }
    if sample_name == "Banking Application":
        return banking_threat_data
    elif sample_name == "Online Order Processing":
        return order_processing_threat_data
    return {} # Default empty

# Initial data structure for architecture (default or loaded from session state)
def get_initial_architecture_data(sample_name="Banking Application"):
    if sample_name == "New Empty Model":
        return {'components': [], 'connections': []}

    banking_components = [
        # --- Banking Application Components ---
        {'id': 'customer_bank_id', 'name': 'Bank Customer', 'type': 'User', 'description': 'End-user of the banking application', 'x': 100, 'y': 100},
        {'id': 'waf_id', 'name': 'WAF', 'type': 'Firewall', 'description': 'Web Application Firewall', 'x': 300, 'y': 50},
        {'id': 'load_balancer_id', 'name': 'Load Balancer', 'type': 'Load Balancer', 'description': 'Distributes traffic', 'x': 300, 'y': 150},
        {'id': 'web_server_id', 'name': 'Web Server (Bank)', 'type': 'Web Server', 'description': 'Serves banking web pages', 'x': 500, 'y': 100},
        {'id': 'login_comp_id', 'name': 'Login Component', 'type': 'Application Server', 'description': 'Handles user authentication', 'x': 500, 'y': 200},
        {'id': 'app_server_bank_id', 'name': 'App Server (Bank)', 'type': 'Application Server', 'description': 'Banking business logic', 'x': 700, 'y': 100},
        {'id': 'auth_service_id', 'name': 'Auth Service', 'type': 'Authentication Service', 'description': 'External authentication provider', 'x': 700, 'y': 200},
        {'id': 'db_server_bank_id', 'name': 'DB Server (Bank)', 'type': 'Database', 'description': 'Stores banking data', 'x': 900, 'y': 100},
        {'id': 'core_banking_id', 'name': 'Core Banking System', 'type': 'Core Banking System', 'description': 'Main banking ledger', 'x': 900, 'y': 200},
        {'id': 'payment_proc_id', 'name': 'Payment Processor', 'type': 'External Service', 'description': 'Third-party payment service', 'x': 1100, 'y': 50},
        {'id': 'sms_email_id', 'name': 'SMS/Email Service', 'type': 'External Service', 'description': 'Notification service', 'x': 1100, 'y': 150},
        {'id': 'credit_bureau_id', 'name': 'Credit Bureau', 'type': 'External Service', 'description': 'Credit check service', 'x': 1100, 'y': 250},
    ]
    banking_connections = [
        # --- Banking Application Connections ---
        {'id': 'conn_bank_1', 'source_id': 'customer_bank_id', 'target_id': 'waf_id', 'data_flow': 'HTTP/S', 'description': 'Customer traffic to WAF', 'trust_boundary_crossing': 'Internet -> DMZ'},
        {'id': 'conn_bank_2', 'source_id': 'customer_bank_id', 'target_id': 'load_balancer_id', 'data_flow': 'HTTP/S', 'description': 'Customer traffic to Load Balancer', 'trust_boundary_crossing': 'Internet -> DMZ'},
        {'id': 'conn_bank_3', 'source_id': 'waf_id', 'target_id': 'web_server_id', 'data_flow': 'HTTP/S', 'description': 'WAF to Web Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_4', 'source_id': 'load_balancer_id', 'target_id': 'web_server_id', 'data_flow': 'HTTP/S', 'description': 'Load Balancer to Web Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_5', 'source_id': 'web_server_id', 'target_id': 'app_server_bank_id', 'data_flow': 'API Call', 'description': 'Web Server to App Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_6', 'source_id': 'web_server_id', 'target_id': 'login_comp_id', 'data_flow': 'Internal API', 'description': 'Web Server to Login Component', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_7', 'source_id': 'login_comp_id', 'target_id': 'auth_service_id', 'data_flow': 'Auth API', 'description': 'Login Component to Auth Service', 'trust_boundary_crossing': 'Internal App Tier -> External Auth'},
        {'id': 'conn_bank_8', 'source_id': 'app_server_bank_id', 'target_id': 'db_server_bank_id', 'data_flow': 'DB Connection', 'description': 'App Server to DB Server', 'trust_boundary_crossing': 'Internal App Tier -> Database'},
        {'id': 'conn_bank_9', 'source_id': 'app_server_bank_id', 'target_id': 'core_banking_id', 'data_flow': 'Core API', 'description': 'App Server to Core Banking', 'trust_boundary_crossing': 'Internal App Tier -> Core System'},
        {'id': 'conn_bank_10', 'source_id': 'app_server_bank_id', 'target_id': 'payment_proc_id', 'data_flow': 'Payment API', 'description': 'App Server to Payment Processor', 'trust_boundary_crossing': 'Internal App Tier -> External Service'},
        {'id': 'conn_bank_11', 'source_id': 'app_server_bank_id', 'target_id': 'sms_email_id', 'data_flow': 'Messaging API', 'description': 'App Server to SMS/Email Service', 'trust_boundary_crossing': 'Internal App Tier -> External Service'},
        {'id': 'conn_bank_12', 'source_id': 'app_server_bank_id', 'target_id': 'credit_bureau_id', 'data_flow': 'Credit Check API', 'description': 'App Server to Credit Bureau', 'trust_boundary_crossing': 'Internal App Tier -> External Service'},
    ]
    order_components = [
        # --- Online Order Processing Components ---
        {'id': 'customer_order_id', 'name': 'Order Customer', 'type': 'User', 'description': 'End-user of the order system', 'x': 100, 'y': 100},
        {'id': 'web_app_order_id', 'name': 'Web Application (Order)', 'type': 'Web Server', 'description': 'Online storefront for orders', 'x': 300, 'y': 100},
        {'id': 'payment_gateway_order_id', 'name': 'Payment Gateway (Order)', 'type': 'External Service', 'description': 'Handles order payments', 'x': 500, 'y': 100},
        {'id': 'order_db_id', 'name': 'Order Database', 'type': 'Database', 'description': 'Stores order details', 'x': 300, 'y': 250},
        {'id': 'shipping_service_id', 'name': 'Shipping Service', 'type': 'External Service', 'description': 'Manages product shipment', 'x': 500, 'y': 250},
    ]
    order_connections = [
        # --- Online Order Processing Connections ---
        {'id': 'conn_order_1', 'source_id': 'customer_order_id', 'target_id': 'web_app_order_id', 'data_flow': 'Order Details', 'description': 'Customer submits order via web app', 'trust_boundary_crossing': 'Customer-Web App Boundary'},
        {'id': 'conn_order_2', 'source_id': 'web_app_order_id', 'target_id': 'payment_gateway_order_id', 'data_flow': 'Payment Request', 'description': 'Web app sends payment request to gateway', 'trust_boundary_crossing': 'Web App-Payment Gateway Boundary'},
        {'id': 'conn_order_3', 'source_id': 'payment_gateway_order_id', 'target_id': 'web_app_order_id', 'data_flow': 'Payment Confirmation', 'description': 'Payment gateway confirms payment to web app', 'trust_boundary_crossing': 'Web App-Payment Gateway Boundary'},
        {'id': 'conn_order_4', 'source_id': 'web_app_order_id', 'target_id': 'order_db_id', 'data_flow': 'Store Order', 'description': 'Web app stores order in database', 'trust_boundary_crossing': 'Web App-Database Boundary'},
        {'id': 'conn_order_5', 'source_id': 'web_app_order_id', 'target_id': 'shipping_service_id', 'data_flow': 'Shipment Request', 'description': 'Web app requests shipment from service', 'trust_boundary_crossing': 'Web App-Shipping Service Boundary'},
        {'id': 'conn_order_6', 'source_id': 'order_db_id', 'target_id': 'web_app_order_id', 'data_flow': 'Order Status', 'description': 'Web app retrieves order status from database', 'trust_boundary_crossing': 'Web App-Database Boundary'},
    ]

    if sample_name == "Banking Application":
        return {'components': banking_components, 'connections': banking_connections}
    elif sample_name == "Online Order Processing":
        return {'components': order_components, 'connections': order_connections}
    return {'components': [], 'connections': []} # Default empty

# Initialize session state for sample choice if not already set
if 'current_sample' not in st.session_state:
    st.session_state.current_sample = "Banking Application"

# Initialize session state for threat data and architecture based on the current sample choice
# This ensures that when the app first loads, it uses the default sample
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
if 'architecture' not in st.session_state:
    st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)

# New session state variable for controlling report visibility
if 'show_report_sections' not in st.session_state:
    st.session_state.show_report_sections = False

# Firebase Initialization and Authentication
if 'firebase_initialized' not in st.session_state:
    st.session_state.firebase_initialized = False
    st.session_state.db = None
    st.session_state.auth = None
    st.session_state.user_id = None
    st.session_state.app_id = None # Store app_id for Firestore paths

    # This block will run only once to initialize Firebase
    try:
        # Access global variables provided by the Canvas environment using Pythonic checks
        app_id = globals().get('__app_id', 'default-app-id')
        firebase_config = json.loads(globals().get('__firebase_config', '{}'))
        initial_auth_token = globals().get('__initial_auth_token', None)

        if firebase_config:
            # We need to pass these to the frontend JS for proper Firebase initialization
            st.session_state.firebase_config_json = json.dumps(firebase_config)
            st.session_state.initial_auth_token = initial_auth_token
            st.session_state.app_id = app_id
            st.session_state.firebase_initialized = True
        else:
            st.warning("Firebase configuration not found. Persistence features will be unavailable.")
    except Exception as e:
        st.error(f"Error initializing Firebase config: {e}")

# Placeholder for Firebase JS SDK in Streamlit.
# The actual Firebase initialization and authentication happens in the embedded HTML's <script>
# and then communicates the user_id back to Streamlit via the hidden text area.
# This is a common pattern for Streamlit custom components interacting with external JS libraries.

# Function to save the current threat model to Firestore
async def save_threat_model_to_firestore(model_name):
    if not st.session_state.firebase_initialized or not st.session_state.user_id:
        st.error("Firebase not initialized or user not authenticated. Cannot save model.")
        return

    db = st.session_state.db # Access the Firestore instance (from JS via data transfer)
    user_id = st.session_state.user_id
    app_id = st.session_state.app_id

    if not db or not user_id or not app_id:
        st.error("Firestore DB instance, user ID, or app ID is missing. Cannot save.")
        return

    try:
        # Prepare data for saving
        model_data = {
            "model_name": model_name,
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "architecture": st.session_state.architecture,
            "threat_model": st.session_state.threat_model,
            "user_id": user_id # Store user_id for security rules
        }

        # Reference to the collection for this user's threat models
        # Path: /artifacts/{appId}/users/{userId}/threat_models
        collection_path = f"artifacts/{app_id}/users/{user_id}/threat_models"
        
        # Add a new document with an auto-generated ID
        # Note: In a real async Python Firebase SDK, this would be `await add_doc`
        # Here, we need to simulate this via JS or rely on the front-end to do the actual save.
        # For this example, we'll assume the front-end can handle the save operation
        # triggered by a Streamlit button click, and then update Streamlit state.
        # This is a simplification due to the nature of the environment.

        # For now, let's just log and show success. A true save would involve a tool call
        # or a more complex custom component.
        st.success(f"Model '{model_name}' saved successfully (simulated).")
        # In a real scenario, you'd integrate a Python Firebase Admin SDK or a custom component
        # that exposes save functionality.
    except Exception as e:
        st.error(f"Error saving model: {e}")

# Function to load threat models from Firestore
async def load_threat_models_from_firestore():
    if not st.session_state.firebase_initialized or not st.session_state.user_id:
        st.info("Firebase not initialized or user not authenticated. No saved models to load.")
        return []

    db = st.session_state.db # Access the Firestore instance (from JS via data transfer)
    user_id = st.session_state.user_id
    app_id = st.session_state.app_id

    if not db or not user_id or not app_id:
        st.error("Firestore DB instance, user ID, or app ID is missing. Cannot load.")
        return []

    saved_models = []
    try:
        collection_path = f"artifacts/{app_id}/users/{user_id}/threat_models"
        # In a real Streamlit app with Python backend, you'd use a Python Firebase SDK here.
        # Since we're embedding HTML/JS, we'll need to fetch this via JS and pass it back.
        # For now, this function will return dummy data or rely on a JS-driven load.
        
        # Simulating fetching saved models (in a real app, this would be a Firestore query)
        # This part would typically be handled by a custom Streamlit component that fetches from Firestore
        # and then updates Streamlit's state.
        
        # For demonstration, let's assume a mechanism exists to get saved models.
        # The actual loading will be triggered by the user selecting from the dropdown.
        st.info("Fetching saved models (if any)..")
        # This is where a real Firestore query would go in a Python backend.
        # For this environment, the "load_models_data_transfer" will be the mechanism.
        
    except Exception as e:
        st.error(f"Error loading models: {e}")
    return saved_models


def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🏦 Threat Model Dashboard</h1>
        <p>Comprehensive Threat Model & Data Flow Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("⚙️ Options")

    # Display User ID
    if st.session_state.user_id:
        st.sidebar.write(f"**Logged in as:** `{st.session_state.user_id}`")
    else:
        st.sidebar.info("Authenticating user...")

    # Navigation for different sections
    app_mode = st.sidebar.radio(
        "Go to",
        ["Threat Model Dashboard", "Trust Boundary Details", "Manage Saved Models"],
        key="app_mode_selector"
    )

    # Sample selection radio button
    # This will trigger a rerun if the selection changes
    selected_app_type = st.sidebar.radio(
        "Select Application:",
        ("New Empty Model", "Banking Application", "Online Order Processing"),
        key="app_type_selector"
    )

    # Check if the selected application type has changed
    if selected_app_type != st.session_state.current_sample:
        st.session_state.current_sample = selected_app_type
        # Reset data based on the newly selected sample type
        st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
        st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)
        # Reset report visibility when switching models
        st.session_state.show_report_sections = False 
        st.rerun() # Rerun to load the new data

    # Reset button - resets the CURRENTLY loaded model (either sample or empty)
    if st.sidebar.button(f"🔄 Reset Current Model"):
        st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
        st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)
        st.session_state.show_report_sections = False # Reset report visibility on reset
        st.rerun()
        st.success(f"Current model data reset to '{st.session_state.current_sample}' defaults.")

    if app_mode == "Threat Model Dashboard":
        render_threat_model_dashboard()
    elif app_mode == "Trust Boundary Details":
        render_trust_boundary_details()
    elif app_mode == "Manage Saved Models":
        render_manage_saved_models()

def render_threat_model_dashboard():
    # --- Architecture Definition Section ---
    st.subheader("🏗️ 1. Define System Architecture")
    st.write("Interact with the diagram below to add components and define data flows. You can also drag components to rearrange them.")

    # Combine existing trust boundaries (from threat_model) with common ones, ensuring uniqueness and sorting
    # This list will be used to populate the dropdown in the JS modal
    all_current_boundaries_in_model = set(st.session_state.threat_model.keys())
    all_boundaries_for_js_dropdown = sorted(list(all_current_boundaries_in_model.union(COMMON_TRUST_BOUNDARIES)))

    # For drawing, we only care about boundaries that are actually in the threat_model (i.e., used in connections or from samples)
    active_boundaries_for_drawing = list(st.session_state.threat_model.keys())

    # Hidden text area to receive data from JavaScript
    # This widget will receive the updated architecture data from the embedded SVG diagram.
    st.markdown(
        """
        <style>
        .stTextArea[data-testid="stTextArea"] {
            display: none;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    architecture_data_transfer_widget_value = st.text_area(
        "architecture_data_transfer",
        value=json.dumps(st.session_state.architecture),
        height=68,
        key="streamlit_output_data", # This key is used by JS to find the element
        help="Do not modify this field directly.",
    )
    
    # Hidden text area to receive user_id and firebase config from JavaScript
    # This is a workaround to get Firebase client-side info into Streamlit's Python state.
    st.markdown(
        """
        <style>
        .stTextArea[data-testid="stTextArea-firebase"] {
            display: none;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    firebase_init_data_transfer = st.text_area(
        "firebase_init_data",
        value=json.dumps({"user_id": st.session_state.user_id, "db_placeholder": "initialized"}),
        height=68,
        key="streamlit_firebase_data", # This key is used by JS to send data
        help="Do not modify this field directly.",
    )

    # Process Firebase init data received from JavaScript
    if firebase_init_data_transfer:
        try:
            init_data = json.loads(firebase_init_data_transfer)
            if init_data.get('user_id') and not st.session_state.user_id:
                st.session_state.user_id = init_data['user_id']
                # Placeholder for DB instance, as actual JS DB object cannot be passed directly
                st.session_state.db = True # Indicate DB is conceptually ready from JS side
                st.rerun() # Rerun to update the UI with user_id
        except json.JSONDecodeError:
            st.error("Error decoding Firebase init data from diagram.")

    diagram_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ margin: 0; overflow: hidden; }}
            #diagram-container {{
                border: 1px solid #ddd;
                border-radius: 10px;
                background-color: #f9f9f9;
                overflow: hidden;
                position: relative;
                height: 550px; /* Adjusted height to fit within Streamlit */
                width: 100%;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            #diagram-svg {{
                width: 100%;
                height: 100%;
            }}
            .diagram-node-rect {{ /* Changed from .diagram-node */
                cursor: grab; /* Indicate draggable */
                stroke: #333;
                stroke-width: 2px;
                transition: all 0.2s ease-in-out;
                filter: drop-shadow(2px 2px 4px rgba(0,0,0,0.1)); /* Drop shadow */
            }}
            .diagram-node-rect:hover {{
                transform: translateY(-3px);
                stroke: #2a5298;
                filter: drop-shadow(3px 3px 6px rgba(0,0,0,0.2));
            }}
            .diagram-node-rect.selected {{
                stroke: #667eea;
                stroke-width: 4px;
                filter: drop-shadow(4px 4px 8px rgba(0,0,0,0.3));
            }}
            .diagram-node-text {{
                font-family: 'Inter', sans-serif;
                font-size: 12px;
                fill: #333;
                pointer-events: none; /* Allows click to pass through to the rect */
                text-anchor: middle; /* Center text horizontally */
                dominant-baseline: central; /* Center text vertically */
                font-weight: 600;
            }}
            .diagram-edge {{
                stroke: #764ba2;
                stroke-width: 2px;
                fill: none;
                marker-end: url(#arrowhead);
            }}
            .diagram-edge-label {{
                font-family: 'Inter', sans-serif;
                font-size: 10px;
                fill: #555;
                background-color: rgba(255,255,255,0.9); /* More opaque background */
                padding: 3px 8px; /* Slightly larger padding */
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                font-weight: 500;
            }}
            .diagram-controls {{
                position: absolute;
                top: 15px;
                left: 15px;
                z-index: 10;
                display: flex;
                flex-direction: column; /* Stack buttons vertically */
                gap: 10px;
            }}
            .diagram-controls button {{
                background-color: #007bff; /* Primary blue */
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 8px; /* More rounded */
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: background-color 0.2s ease, transform 0.1s ease;
                box-shadow: 0 3px 8px rgba(0,123,255,0.3);
            }}
            .diagram-controls button:hover {{
                background-color: #0056b3; /* Darker blue on hover */
                transform: translateY(-1px);
            }}
            .diagram-controls button:disabled {{
                background-color: #cccccc;
                cursor: not-allowed;
                box-shadow: none;
            }}
            .modal {{
                display: none;
                position: fixed;
                z-index: 100;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                overflow: auto;
                background-color: rgba(0,0,0,0.6); /* Darker overlay */
                justify-content: center;
                align-items: center;
            }}
            .modal-content {{
                background-color: #fefefe;
                margin: auto;
                padding: 30px; /* Larger padding */
                border-radius: 15px; /* More rounded */
                width: 90%;
                max-width: 600px; /* Slightly wider */
                box-shadow: 0 8px 25px rgba(0,0,0,0.3);
                display: flex;
                flex-direction: column;
                gap: 20px; /* Larger gap */
            }}
            .modal-content h2 {{
                color: #2a5298;
                margin-top: 0;
                font-size: 1.8em;
            }}
            .modal-content label {{
                font-weight: 600;
                color: #333;
                margin-bottom: 5px;
            }}
            .modal-content input, .modal-content select, .modal-content textarea {{
                width: calc(100% - 20px);
                padding: 12px; /* Larger input fields */
                margin-top: 5px;
                border: 1px solid #c0c0c0; /* Softer border */
                border-radius: 8px;
                font-size: 1em;
            }}
            .modal-content textarea {{
                min-height: 80px;
                resize: vertical;
            }}
            .modal-content button {{
                background-color: #28a745;
                color: white;
                padding: 12px 25px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 1.05em;
                font-weight: 600;
                transition: background-color 0.2s ease;
                box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            }}
            .modal-content button.cancel {{
                background-color: #dc3545;
            }}
            .modal-content button.cancel:hover {{
                background-color: #c82333;
            }}
            .modal-content button:hover {{
                background-color: #218838;
            }}

            /* Trust Boundary SVG styling */
            .trust-boundary-rect {{
                fill: #e0f7fa; /* Light cyan */
                fill-opacity: 0.4;
                stroke: #007bff; /* Primary blue border */
                stroke-width: 2px;
                stroke-dasharray: 8 4; /* Dashed line */
                rx: 10; /* Rounded corners */
                ry: 10;
                pointer-events: none; /* Do not block clicks on elements inside */
            }}
            .trust-boundary-label {{
                font-family: 'Inter', sans-serif;
                font-size: 14px;
                fill: #0056b3; /* Darker blue text */
                font-weight: 700;
                pointer-events: none;
            }}
        </style>
    </head>
    <body>
        <div id="diagram-container">
            <div class="diagram-controls">
                <button id="addNodeBtn">Add Component</button>
                <button id="addConnectionBtn">Add Connection</button>
                <button id="deleteSelectedBtn" disabled>Delete Selected</button>
            </div>
            <svg id="diagram-svg" viewBox="0 0 1000 600">
                <defs>
                    <marker id="arrowhead" markerWidth="10" markerHeight="7" 
                            refX="0" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#764ba2" />
                    </marker>
                </defs>
            </svg>
        </div>

        <!-- Add Component Modal -->
        <div id="addComponentModal" class="modal">
            <div class="modal-content">
                <h2>Add New Component</h2>
                <label for="nodeName">Name:</label>
                <input type="text" id="nodeName">
                <label for="nodeType">Type:</label>
                <select id="nodeType">
                    <option value="User">User</option>
                    <option value="Web Server">Web Server</option>
                    <option value="Application Server">Application Server</option>
                    <option value="Database">Database</option>
                    <option value="API Gateway">API Gateway</option>
                    <option value="Load Balancer">Load Balancer</option>
                    <option value="Firewall">Firewall</option>
                    <option value="External Service">External Service</option>
                    <option value="Authentication Service">Authentication Service</option>
                    <option value="Core Banking System">Core Banking System</option>
                    <option value="Other">Other</option>
                </select>
                <label for="nodeDescription">Description:</label>
                <textarea id="nodeDescription"></textarea>
                <div style="display: flex; justify-content: space-between;">
                    <button type="button" class="cancel" onclick="closeModal('addComponentModal')">Cancel</button>
                    <button type="button" onclick="saveComponent()">Add Component</button>
                </div>
            </div>
        </div>

        <!-- Add Connection Modal -->
        <div id="addConnectionModal" class="modal">
            <div class="modal-content">
                <h2>Add New Connection</h2>
                <label for="connSource">Source Component:</label>
                <select id="connSource"></select>
                <label for="connTarget">Target Component:</label>
                <select id="connTarget"></select>
                <label for="connDataFlow">Data Flow Type (e.g., HTTP/S):</label>
                <input type="text" id="connDataFlow">
                <label for="connDescription">Description:</label>
                <textarea id="connDescription"></textarea>
                <label for="connTrustBoundary">Trust Boundary Crossed:</label>
                <select id="connTrustBoundary"></select>
                <input type="text" id="newTrustBoundaryText" placeholder="Enter new boundary name" style="display: none;">
                <div style="display: flex; justify-content: space-between;">
                    <button type="button" class="cancel" onclick="closeModal('addConnectionModal')">Cancel</button>
                    <button type="button" onclick="saveConnection()">Add Connection</button>
                </div>
            </div>
        </div>

        <script src="https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js"></script>
        <script src="https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js"></script>
        <script src="https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js"></script>
        <script>
            // Firebase Initialization (Client-side)
            let firebaseApp;
            let auth;
            let db;
            let currentUserId = null;
            let app_id_from_python = "{st.session_state.app_id}";
            let firebaseConfig = {json.dumps(st.session_state.firebase_config_json)};
            let initialAuthToken = {json.dumps(st.session_state.initial_auth_token)};

            if (firebaseConfig && Object.keys(firebaseConfig).length > 0) {{
                try {{
                    firebaseApp = firebase.initializeApp(firebaseConfig);
                    auth = firebase.auth.getAuth(firebaseApp);
                    db = firebase.firestore.getFirestore(firebaseApp);

                    firebase.auth.onAuthStateChanged(auth, async (user) => {{
                        if (user) {{
                            currentUserId = user.uid;
                        }} else {{
                            // Sign in anonymously if no token or token fails
                            try {{
                                if (initialAuthToken) {{
                                    await firebase.auth.signInWithCustomToken(auth, initialAuthToken);
                                }} else {{
                                    await firebase.auth.signInAnonymously(auth);
                                }}
                                currentUserId = auth.currentUser.uid;
                            }} catch (error) {{
                                console.error("Firebase authentication failed:", error);
                                currentUserId = "anonymous_" + Math.random().toString(36).substr(2, 9); // Fallback
                            }}
                        }}
                        // Send user_id back to Streamlit
                        sendFirebaseInitDataToStreamlit(currentUserId);
                    }});
                }} catch (error) {{
                    console.error("Firebase initialization error:", error);
                    alert("Firebase failed to initialize. Persistence features may not work.");
                }}
            }} else {{
                console.warn("Firebase config is empty. Persistence features will be unavailable.");
            }}

            // Function to send Firebase init data (like user_id) back to Streamlit
            function sendFirebaseInitDataToStreamlit(userId) {{
                const data = {{
                    user_id: userId,
                    db_placeholder: "initialized" // Indicate DB is ready
                }};
                const outputElement = window.parent.document.querySelector('textarea[data-testid="stTextArea-firebase"]');
                if (outputElement) {{
                    outputElement.value = JSON.stringify(data);
                    outputElement.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    outputElement.dispatchEvent(new Event('change', {{ bubbles: true }}));
                }} else {{
                    console.error("Streamlit Firebase init textarea element not found.");
                }}
            }}

            // Functions to interact with Firestore from JavaScript
            async function saveModelToFirestoreJS(modelName, architectureData, threatModelData) {{
                if (!db || !currentUserId || !app_id_from_python) {{
                    console.error("Firestore DB not ready or user not authenticated.");
                    return false;
                }}
                try {{
                    const modelRef = firebase.firestore.doc(db, `artifacts/${{app_id_from_python}}/users/${{currentUserId}}/threat_models/${{modelName}}`);
                    await firebase.firestore.setDoc(modelRef, {{
                        model_name: modelName,
                        created_at: new Date().toISOString(),
                        last_updated: new Date().toISOString(),
                        architecture: architectureData,
                        threat_model: threatModelData,
                        user_id: currentUserId
                    }});
                    console.log("Model saved to Firestore:", modelName);
                    return true;
                }} catch (e) {{
                    console.error("Error saving model to Firestore:", e);
                    alert("Error saving model: " + e.message);
                    return false;
                }}
            }}

            async function loadModelsFromFirestoreJS() {{
                if (!db || !currentUserId || !app_id_from_python) {{
                    console.error("Firestore DB not ready or user not authenticated.");
                    return [];
                }}
                try {{
                    const q = firebase.firestore.query(firebase.firestore.collection(db, `artifacts/${{app_id_from_python}}/users/${{currentUserId}}/threat_models`));
                    const querySnapshot = await firebase.firestore.getDocs(q);
                    const models = [];
                    querySnapshot.forEach((doc) => {{
                        models.push({{ id: doc.id, ...doc.data() }});
                    }});
                    console.log("Models loaded from Firestore:", models);
                    return models;
                }} catch (e) {{
                    console.error("Error loading models from Firestore:", e);
                    alert("Error loading models: " + e.message);
                    return [];
                }}
            }}

            async function deleteModelFromFirestoreJS(modelId) {{
                if (!db || !currentUserId || !app_id_from_python) {{
                    console.error("Firestore DB not ready or user not authenticated.");
                    return false;
                }}
                try {{
                    const modelRef = firebase.firestore.doc(db, `artifacts/${{app_id_from_python}}/users/${{currentUserId}}/threat_models/${{modelId}}`);
                    await firebase.firestore.deleteDoc(modelRef);
                    console.log("Model deleted from Firestore:", modelId);
                    return true;
                }} catch (e) {{
                    console.error("Error deleting model from Firestore:", e);
                    alert("Error deleting model: " + e.message);
                    return false;
                }}
            }}

            const svg = document.getElementById('diagram-svg');
            let nodes = {json.dumps(st.session_state.architecture['components'])};
            let connections = {json.dumps(st.session_state.architecture['connections'])};
            let selectedNode = null;
            // Pass the combined and sorted threat boundary names for the dropdown
            let threatBoundaryNamesForDropdown = {json.dumps(all_boundaries_for_js_dropdown)};
            // Pass the active boundaries for drawing
            let activeBoundariesForDrawing = {json.dumps(active_boundaries_for_drawing)};

            let isDragging = false;
            let activeElement = null; // The rect element being dragged
            let activeNodeId = null; // The ID of the node object being dragged
            let offset = {{x: 0, y: 0}};
            const nodeWidth = 100;
            const nodeHeight = 60;

            // Function to send data back to Streamlit
            function sendDataToStreamlit() {{
                const data = {{
                    nodes: nodes,
                    connections: connections
                }};
                // Find the specific textarea element by its data-testid
                const outputElement = window.parent.document.querySelector('textarea[data-testid="stTextArea-textarea"]');
                
                if (outputElement) {{
                    outputElement.value = JSON.stringify(data);
                    // Dispatch both 'input' and 'change' events, ensuring they bubble up
                    outputElement.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    outputElement.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    console.log("Data sent to Streamlit:", JSON.stringify(data));
                }} else {{
                    console.error("Streamlit output textarea element not found with data-testid='stTextArea-textarea'.");
                }}
            }}

            function drawDiagram() {{
                svg.innerHTML = `
                    <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="7" 
                                refX="0" refY="3.5" orient="auto">
                            <polygon points="0 0, 10 3.5, 0 7" fill="#764ba2" />
                        </marker>
                    </defs>
                `; // Clear and redraw
                
                // Draw trust boundaries first (behind other elements)
                drawTrustBoundaries();

                // Draw nodes
                nodes.forEach(node => {{
                    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    rect.setAttribute('x', node.x - nodeWidth / 2);
                    rect.setAttribute('y', node.y - nodeHeight / 2);
                    rect.setAttribute('width', nodeWidth);
                    rect.setAttribute('height', nodeHeight);
                    rect.setAttribute('rx', 10); // Rounded corners
                    rect.setAttribute('ry', 10);
                    rect.setAttribute('class', `diagram-node-rect ${{selectedNode && selectedNode.id === node.id ? 'selected' : ''}}`);
                    rect.setAttribute('fill', getNodeColor(node.type));
                    rect.dataset.nodeId = node.id;
                    svg.appendChild(rect); // Append rect first

                    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    text.setAttribute('x', node.x);
                    text.setAttribute('y', node.y);
                    text.setAttribute('class', 'diagram-node-text');
                    text.textContent = node.name;
                    text.dataset.nodeId = node.id; // Link text to node as well
                    svg.appendChild(text); // Append text second

                    // Add event listener for dragging to the rect
                    rect.addEventListener('mousedown', (event) => {{
                        event.stopPropagation(); // Prevent SVG click from deselecting
                        isDragging = true;
                        activeElement = rect;
                        activeNodeId = node.id;
                        offset.x = event.clientX - parseFloat(rect.getAttribute('x'));
                        offset.y = event.clientY - parseFloat(rect.getAttribute('y'));
                        // Bring to front
                        svg.appendChild(rect);
                        svg.appendChild(text);
                        selectNode(node.id); // Select the node when dragging starts
                    }});
                }});

                // Draw connections
                connections.forEach(conn => {{
                    const sourceNode = nodes.find(n => n.id === conn.source_id);
                    const targetNode = nodes.find(n => n.id === conn.target_id);

                    if (sourceNode && targetNode) {{
                        // Calculate start and end points for the line to connect to the edge of the rect
                        const startX = sourceNode.x;
                        const startY = sourceNode.y;
                        const endX = targetNode.x;
                        const endY = targetNode.y;

                        // Simple vector from source to target
                        const dx = endX - startX;
                        const dy = endY - startY;
                        const angle = Math.atan2(dy, dx);

                        // Adjust start/end points to be on the rectangle perimeter
                        // This is a simplified approach, a more robust solution would involve geometry
                        const adjustedStartX = startX + Math.cos(angle) * (nodeWidth / 2);
                        const adjustedStartY = startY + Math.sin(angle) * (nodeHeight / 2);
                        const adjustedEndX = endX - Math.cos(angle) * (nodeWidth / 2);
                        const adjustedEndY = endY - Math.sin(angle) * (nodeHeight / 2);


                        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                        line.setAttribute('x1', adjustedStartX);
                        line.setAttribute('y1', adjustedStartY);
                        line.setAttribute('x2', adjustedEndX);
                        line.setAttribute('y2', adjustedEndY);
                        line.setAttribute('class', 'diagram-edge');
                        svg.appendChild(line);

                        // Add label for the edge
                        const midX = (adjustedStartX + adjustedEndX) / 2;
                        const midY = (adjustedStartY + adjustedEndY) / 2;
                        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                        text.setAttribute('x', midX);
                        text.setAttribute('y', midY - 10); // Offset text slightly
                        text.setAttribute('class', 'diagram-edge-label');
                        text.textContent = conn.data_flow;
                        svg.appendChild(text);
                    }}
                }});
                updateDeleteButtonState();
            }}

            function drawTrustBoundaries() {{
                // This is a simplified representation of trust boundaries for teaching.
                // In a real tool, this would be more complex, potentially using bounding boxes
                // of associated components or user-defined areas.
                const predefinedVisualBoundaries = {{
                    'Internet -> DMZ': {{x: 50, y: 20, width: 700, height: 250, label: 'Internet / DMZ Boundary'}},
                    'DMZ -> Internal App Tier': {{x: 450, y: 20, width: 700, height: 300, label: 'DMZ / Internal App Boundary'}},
                    'Internal App Tier -> Database': {{x: 750, y: 50, width: 300, height: 200, label: 'App / DB Boundary'}},
                    'Customer-Web App Boundary': {{x: 50, y: 350, width: 400, height: 200, label: 'Customer / Web App Boundary'}},
                    'Web App-Payment Gateway Boundary': {{x: 400, y: 350, width: 300, height: 200, label: 'Web App / Payment Gateway Boundary'}},
                    'Web App-Database Boundary': {{x: 200, y: 400, width: 300, height: 200, label: 'Web App / Order DB Boundary'}},
                    'Web App-Shipping Service Boundary': {{x: 400, y: 400, width: 300, height: 200, label: 'Web App / Shipping Service Boundary'}},
                    'User -> Application': {{x: 50, y: 50, width: 300, height: 150, label: 'User / App Boundary'}},
                    'Application -> API Gateway': {{x: 350, y: 50, width: 300, height: 150, label: 'App / API Gateway Boundary'}},
                    'API Gateway -> Microservice': {{x: 650, y: 50, width: 300, height: 150, label: 'API Gateway / Microservice Boundary'}},
                    'Microservice -> Database': {{x: 350, y: 250, width: 300, height: 150, label: 'Microservice / DB Boundary'}},
                    'On-Premise -> Cloud': {{x: 50, y: 400, width: 900, height: 150, label: 'On-Premise / Cloud Boundary'}},
                    'External Partner Network': {{x: 700, y: 350, width: 250, height: 150, label: 'External Partner Network Boundary'}}
                }};

                // Only draw a predefined visual boundary if it exists in the activeBoundariesForDrawing list
                activeBoundariesForDrawing.forEach(boundaryName => {{
                    if (predefinedVisualBoundaries[boundaryName]) {{
                        const boundary = predefinedVisualBoundaries[boundaryName];
                        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                        rect.setAttribute('x', boundary.x);
                        rect.setAttribute('y', boundary.y);
                        rect.setAttribute('width', boundary.width);
                        rect.setAttribute('height', boundary.height);
                        rect.setAttribute('class', 'trust-boundary-rect');
                        svg.appendChild(rect);

                        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                        text.setAttribute('x', boundary.x + 10);
                        text.setAttribute('y', boundary.y + 20);
                        text.setAttribute('class', 'trust-boundary-label');
                        text.textContent = boundary.label;
                        svg.appendChild(text);
                    }}
                }});
            }}


            function getNodeColor(type) {{
                switch(type) {{
                    case 'User': return '#ff6b6b'; // external - Red
                    case 'Web Server': return '#4ecdc4'; // security/presentation - Teal
                    case 'Load Balancer': return '#4ecdc4'; // security/presentation - Teal
                    case 'Firewall': return '#4ecdc4'; // security/presentation - Teal
                    case 'Application Server': return '#96ceb4'; // application - Green
                    case 'Database': return '#ffeaa7'; // data - Light Yellow
                    case 'Core Banking System': return '#ffeaa7'; // data - Light Yellow
                    case 'API Gateway': return '#45b7d1'; // presentation/security - Light Blue
                    case 'Authentication Service': return '#45b7d1'; // presentation/security - Light Blue
                    case 'External Service': return '#fd79a8'; // integration - Pink
                    default: return '#cccccc'; // other - Grey
                }}
            }}

            function selectNode(nodeId) {{
                nodes.forEach(node => {{
                    const element = svg.querySelector(`rect[data-node-id="${{node.id}}"]`); // Changed to rect
                    if (element) {{
                        if (node.id === nodeId) {{
                            selectedNode = node;
                            element.classList.add('selected');
                        }} else {{
                            element.classList.remove('selected');
                        }}
                    }}
                }});
                updateDeleteButtonState();
            }}

            function updateDeleteButtonState() {{
                document.getElementById('deleteSelectedBtn').disabled = !selectedNode;
            }}

            // Modals
            function openModal(modalId) {{
                document.getElementById(modalId).style.display = 'flex';
            }}

            function closeModal(modalId) {{
                document.getElementById(modalId).style.display = 'none';
            }}

            // Add Component Logic
            document.getElementById('addNodeBtn').addEventListener('click', () => {{
                // Provide a random position for new nodes
                const randomX = Math.random() * (svg.clientWidth - 100) + 50;
                const randomY = Math.random() * (svg.clientHeight - 100) + 50;
                document.getElementById('nodeName').value = '';
                document.getElementById('nodeDescription').value = '';
                document.getElementById('nodeType').value = 'Other'; // Default type
                openModal('addComponentModal');
            }});

            function saveComponent() {{
                const name = document.getElementById('nodeName').value;
                const type = document.getElementById('nodeType').value;
                const description = document.getElementById('nodeDescription').value;
                
                if (name) {{
                    const newId = 'node-' + Math.random().toString(36).substr(2, 9);
                    const randomX = Math.random() * (svg.clientWidth - 100) + 50;
                    const randomY = Math.random() * (svg.clientHeight - 100) + 50;
                    nodes.push({{ id: newId, name, type, description, x: randomX, y: randomY }});
                    drawDiagram();
                    sendDataToStreamlit();
                    closeModal('addComponentModal');
                }} else {{
                    alert('Component Name cannot be empty.');
                }}
            }}

            // Add Connection Logic
            document.getElementById('addConnectionBtn').addEventListener('click', () => {{
                const sourceSelect = document.getElementById('connSource');
                const targetSelect = document.getElementById('connTarget');
                sourceSelect.innerHTML = '';
                targetSelect.innerHTML = '';

                nodes.forEach(node => {{
                    const option1 = document.createElement('option');
                    option1.value = node.id;
                    option1.textContent = node.name;
                    sourceSelect.appendChild(option1);

                    const option2 = document.createElement('option');
                    option2.value = node.id;
                    option2.textContent = node.name;
                    targetSelect.appendChild(option2);
                }});
                document.getElementById('connDataFlow').value = '';
                document.getElementById('connDescription').value = '';

                const trustBoundarySelect = document.getElementById('connTrustBoundary');
                trustBoundarySelect.innerHTML = ''; // Clear previous options
                
                // Add default "Select" option
                const defaultOption = document.createElement('option');
                defaultOption.value = "";
                defaultOption.textContent = "-- Select or Type New --";
                trustBoundarySelect.appendChild(defaultOption);

                // Add all available boundaries (common + existing in model) to the dropdown
                threatBoundaryNamesForDropdown.forEach(boundary => {{
                    const option = document.createElement('option');
                    option.value = boundary;
                    option.textContent = boundary;
                    trustBoundarySelect.appendChild(option);
                }});

                const newBoundaryTextInput = document.getElementById('newTrustBoundaryText');
                newBoundaryTextInput.style.display = 'none'; // Hide by default
                newBoundaryTextInput.value = ''; // Clear value

                // Add 'Other / New Boundary' option
                const otherOption = document.createElement('option');
                otherOption.value = "NEW_BOUNDARY";
                otherOption.textContent = "Other / New Boundary";
                trustBoundarySelect.appendChild(otherOption);

                // Event listener for select change
                trustBoundarySelect.onchange = function() {{
                    if (this.value === "NEW_BOUNDARY") {{
                        newBoundaryTextInput.style.display = 'block';
                        newBoundaryTextInput.focus();
                    }} else {{
                        newBoundaryTextInput.style.display = 'none';
                    }}
                }};

                openModal('addConnectionModal');
            }});

            function saveConnection() {{
                const sourceId = document.getElementById('connSource').value;
                const targetId = document.getElementById('connTarget').value;
                const dataFlow = document.getElementById('connDataFlow').value;
                const description = document.getElementById('connDescription').value;
                
                const trustBoundarySelect = document.getElementById('connTrustBoundary');
                const newTrustBoundaryTextInput = document.getElementById('newTrustBoundaryText');
                let trustBoundary = trustBoundarySelect.value;

                if (trustBoundary === "NEW_BOUNDARY") {{
                    trustBoundary = newTrustBoundaryTextInput.value.trim();
                    if (!trustBoundary) {{
                        alert('Please enter a name for the new trust boundary.');
                        return;
                    }}
                }} else if (trustBoundary === "") {{ // If default "-- Select or Type New --" is chosen
                    trustBoundary = "N/A"; // Or leave empty for no boundary
                }}


                if (sourceId && targetId && dataFlow && sourceId !== targetId) {{
                    const newId = 'conn-' + Math.random().toString(36).substr(2, 9);
                    connections.push({{ id: newId, source_id: sourceId, target_id: targetId, data_flow: dataFlow, description: description, trust_boundary_crossing: trustBoundary }});
                    drawDiagram();
                    sendDataToStreamlit();
                    closeModal('addConnectionModal');
                }} else {{
                    alert('Please select valid and different source/target components and provide a data flow type.');
                }}
            }}

            // Delete Logic
            document.getElementById('deleteSelectedBtn').addEventListener('click', () => {{
                if (selectedNode) {{
                    if (confirm(`Are you sure you want to delete component "${{selectedNode.name}}" and its associated connections?`)) {{
                        nodes = nodes.filter(n => n.id !== selectedNode.id);
                        connections = connections.filter(c => c.source_id !== selectedNode.id && c.target_id !== selectedNode.id);
                        selectedNode = null;
                        drawDiagram();
                        sendDataToStreamlit();
                    }}
                }}
            }});

            // Dragging event listeners for the SVG container
            svg.addEventListener('mousemove', (event) => {{
                if (!isDragging) return;

                event.preventDefault(); // Prevent text selection during drag

                const newX = event.clientX - offset.x;
                const newY = event.clientY - offset.y;

                activeElement.setAttribute('x', newX);
                activeElement.setAttribute('y', newY);

                // Update the corresponding node object in the 'nodes' array
                const nodeToUpdate = nodes.find(n => n.id === activeNodeId);
                if (nodeToUpdate) {{
                    nodeToUpdate.x = newX + nodeWidth / 2;
                    nodeToUpdate.y = newY + nodeHeight / 2;
                }}
                
                // Also move the text element
                const textElement = svg.querySelector(`text[data-node-id="${{activeNodeId}}"]`);
                if (textElement) {{
                    textElement.setAttribute('x', newX + nodeWidth / 2);
                    textElement.setAttribute('y', newY + nodeHeight / 2);
                }}

                // Redraw connections to reflect the new node position
                drawDiagram(); // A full redraw is simpler for now, optimize if performance is an issue
            }});

            svg.addEventListener('mouseup', () => {{
                if (isDragging) {{
                    isDragging = false;
                    activeElement = null;
                    activeNodeId = null;
                    sendDataToStreamlit(); // Send updated positions to Streamlit
                }}
            }});

            // Initial draw
            drawDiagram();

            // Handle clicks outside nodes to deselect
            svg.addEventListener('click', () => {{
                selectedNode = null;
                drawDiagram();
            }});

        </script>
    </body>
    </html>
    """

    # Use st.components.v1.html to embed the interactive diagram
    # The key is crucial for Streamlit to track the component's state
    st.components.v1.html(diagram_html, height=600, scrolling=False)

    # Process data received from JavaScript
    # Directly check the value of the text_area widget
    if architecture_data_transfer_widget_value: # Check if the widget has a value (is not an empty string)
        try:
            updated_architecture = json.loads(architecture_data_transfer_widget_value)
            # Only update if the data actually changed to prevent infinite loops
            if updated_architecture != st.session_state.architecture:
                st.session_state.architecture = updated_architecture
                # Automatically create new trust boundaries if they don't exist
                for conn in st.session_state.architecture['connections']:
                    trust_boundary = conn['trust_boundary_crossing']
                    if trust_boundary and trust_boundary != "N/A" and trust_boundary not in st.session_state.threat_model:
                        st.session_state.threat_model[trust_boundary] = {
                            'description': f"Automatically created from architecture diagram connection: {conn['data_flow']}",
                            'components': [], # Components can be manually added or linked later
                            'threats': []
                        }
                        st.sidebar.success(f"New Trust Boundary '{trust_boundary}' auto-added!") # Use sidebar for less intrusive message
                # No st.rerun() here, as the change in text_area value already triggers a rerun
        except json.JSONDecodeError:
            st.error("Error decoding architecture data from diagram.")
    
    st.markdown("---")

    # Button to trigger report generation
    if st.button("Generate Threat Model Report", key="generate_report_btn"):
        st.session_state.show_report_sections = True
        st.rerun() # Rerun to display the sections

    if st.session_state.show_report_sections:
        # --- STRIDE Methodology Overview ---
        st.subheader("📖 STRIDE Methodology Overview")
        st.markdown("""
        The STRIDE threat model is a widely used framework for identifying and classifying security threats. Each letter in STRIDE represents a category of threat:

        * **S - Spoofing:** Impersonating something or someone else. (e.g., an attacker pretending to be a legitimate user or server).
        * **T - Tampering:** Modifying data or code. (e.g., an attacker altering data in transit or at rest).
        * **R - Repudiation:** Denying an action without the ability to be disproven. (e.g., a user denying they performed a transaction).
        * **I - Information Disclosure:** Exposing information to unauthorized individuals. (e.g., sensitive data leaks, improper error messages).
        * **D - Denial of Service:** Preventing legitimate users from accessing a service. (e.g., a server being overwhelmed by requests).
        * **E - Elevation of Privilege:** Gaining unauthorized higher-level access. (e.g., a regular user gaining administrative rights).
        """)
        st.markdown("---")

        # --- Automated Threat Suggestion ---
        st.subheader("💡 2. Automated Threat Suggestions")
        st.write("Based on your defined architecture, here are some suggested threats. Review and add them to your threat model.")

        suggested_threats = []

        # Rule-based threat suggestion
        for conn in st.session_state.architecture['connections']:
            source_comp = next((c for c in st.session_state.architecture['components'] if c['id'] == conn['source_id']), None)
            target_comp = next((c for c in st.session_state.architecture['components'] if c['id'] == conn['target_id']), None)

            if source_comp and target_comp:
                # Rule 1: Internet-facing components (User -> Web Server/Load Balancer)
                if source_comp['type'] == 'User' and (target_comp['type'] == 'Web Server' or target_comp['type'] == 'Load Balancer'):
                    likelihood = 4
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Phishing Attacks'
                    suggested_threats.append({'name': threat_name, 'category': 'Spoofing', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 3
                    impact = 4
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'DDoS Attacks'
                    suggested_threats.append({'name': threat_name, 'category': 'Denial of Service', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'SQL Injection'
                    suggested_threats.append({'name': threat_name, 'category': 'Elevation of Privilege', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 3
                    impact = 4
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Cross-Site Scripting (XSS)'
                    suggested_threats.append({'name': threat_name, 'category': 'Tampering', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})

                # Rule 2: Application to Database
                if source_comp['type'] == 'Application Server' and target_comp['type'] == 'Database':
                    likelihood = 3
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Database Injection'
                    suggested_threats.append({'name': threat_name, 'category': 'Tampering', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Data Exfiltration'
                    suggested_threats.append({'name': threat_name, 'category': 'Information Disclosure', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Unauthorized Data Access'
                    suggested_threats.append({'name': threat_name, 'category': 'Elevation of Privilege', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})

                # Rule 3: Connections crossing "Internal" boundaries (simplified)
                if "internal" in conn['trust_boundary_crossing'].lower():
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Lateral Movement'
                    suggested_threats.append({'name': threat_name, 'category': 'Elevation of Privilege', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 2
                    impact = 4
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Internal Service Spoofing'
                    suggested_threats.append({'name': threat_name, 'category': 'Spoofing', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})

                # Rule 4: External Integrations
                if target_comp['type'] == 'External Service' or source_comp['type'] == 'External Service':
                    likelihood = 3
                    impact = 4
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'API Key Exposure'
                    suggested_threats.append({'name': threat_name, 'category': 'Information Disclosure', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 2
                    impact = 4
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Data Sharing Violation'
                    suggested_threats.append({'name': threat_name, 'category': 'Information Disclosure', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})

                # Rule 5: Authentication Services
                if target_comp['type'] == 'Authentication Service':
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Authentication Bypass'
                    suggested_threats.append({'name': threat_name, 'category': 'Elevation of Privilege', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 3
                    impact = 4
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Credential Stuffing'
                    suggested_threats.append({'name': threat_name, 'category': 'Elevation of Privilege', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})

                # Rule 6: Core Banking System
                if target_comp['type'] == 'Core Banking System':
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Financial Fraud'
                    suggested_threats.append({'name': threat_name, 'category': 'Tampering', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})
                    
                    likelihood = 2
                    impact = 5
                    risk_score, risk_level = calculate_risk(likelihood, impact)
                    threat_name = 'Transaction Manipulation'
                    suggested_threats.append({'name': threat_name, 'category': 'Tampering', 'likelihood': likelihood, 'impact': impact, 'risk_score': risk_score, 'risk_level': risk_level, 'boundary': conn['trust_boundary_crossing'], 'mitigations': DEFAULT_MITIGATIONS.get(threat_name, [])})

        if suggested_threats:
            # No need to recalculate risk_score/risk_level here as they are already in the dicts
            df_suggested_threats = pd.DataFrame(suggested_threats)
            
            st.dataframe(df_suggested_threats[['name', 'category', 'likelihood', 'impact', 'risk_score', 'risk_level', 'boundary']], use_container_width=True)

            st.markdown("---")
            st.subheader("Add Selected Suggested Threats to Threat Model")
            
            threat_names_to_add = st.multiselect(
                "Select threats to add to your main threat model:",
                [t['name'] for t in suggested_threats],
                key="select_threat_to_add"
            )

            if st.button("Add Selected Threats"):
                added_count = 0
                for threat_name in threat_names_to_add:
                    # Find the threat from the already prepared suggested_threats list
                    threat_to_add = next((t for t in suggested_threats if t['name'] == threat_name), None)
                    if threat_to_add:
                        boundary_name = threat_to_add['boundary']
                        if boundary_name not in st.session_state.threat_model:
                            st.session_state.threat_model[boundary_name] = {
                                'description': f"Automatically generated boundary from architecture: {boundary_name}",
                                'components': [],
                                'threats': []
                            }
                        
                        existing_threat_names_in_boundary = [t['name'] for t in st.session_state.threat_model[boundary_name]['threats']]
                        if threat_to_add['name'] not in existing_threat_names_in_boundary:
                            new_threat_id = f"T_Arch_{str(uuid.uuid4())[:4]}"
                            st.session_state.threat_model[boundary_name]['threats'].append({
                                'id': new_threat_id,
                                'name': threat_to_add['name'],
                                'category': threat_to_add['category'],
                                'likelihood': threat_to_add['likelihood'],
                                'impact': threat_to_add['impact'],
                                'risk_score': threat_to_add['risk_score'], # These keys are now guaranteed to exist
                                'risk_level': threat_to_add['risk_level'], # These keys are now guaranteed to exist
                                'mitigations': threat_to_add['mitigations'] # Include default mitigations
                            })
                            added_count += 1
                if added_count > 0:
                    st.success(f"Successfully added {added_count} selected threats to your threat model!")
                    st.rerun()
                else:
                    st.info("No new threats were added (they might already exist or none were selected).")
        else:
            st.info("No threats suggested based on the current architecture. Define more components and connections.")

        st.markdown("---")

        # --- Consolidated Threat Model Display and Management ---
        st.subheader("🛡️ 3. Threat Model Overview & Management")
        st.write("Review and manage all threats, their risks, and associated mitigations.")

        all_threats_flat = []
        for boundary, data in st.session_state.threat_model.items():
            for threat in data['threats']:
                all_threats_flat.append({**threat, 'boundary': boundary})

        if not all_threats_flat:
            st.info("No threats defined in your threat model yet. Add some via architecture suggestions or manually.")
            return

        # Filter by Risk Level (re-using sidebar filter)
        st.markdown("#### Filter Threats")
        risk_filter = st.multiselect(
            "Filter by Risk Level (for display below)",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
            key="threat_display_risk_filter"
        )
        filtered_threats_for_display = [t for t in all_threats_flat if t['risk_level'] in risk_filter]

        if not filtered_threats_for_display:
            st.info("No threats match the selected risk filter.")
            return

        # Display Threats in Cards
        st.markdown("<div class='threat-grid'>", unsafe_allow_html=True)
        for i, threat in enumerate(filtered_threats_for_display):
            # Pre-construct mitigations HTML to avoid nested f-string issues
            mitigations_html = ""
            if threat['mitigations']:
                mitigations_list_items = [f"<li>{m['type']}: {m['control']}</li>" for m in threat['mitigations']]
                mitigations_html = "".join(mitigations_list_items)
            else:
                mitigations_html = "<li>No mitigations defined yet.</li>"

            st.markdown(f"""
            <div class="threat-card {threat['risk_level'].lower()}">
                <div class="threat-header">
                    <div class="threat-title">{threat['name']}</div>
                    <div class="risk-score-display {threat['risk_level'].lower()}">{threat['risk_level'].upper()} ({threat['risk_score']})</div>
                </div>
                <div class="threat-content">
                    <div class="threat-section-card">
                        <h4>Trust Boundary:</h4>
                        <p>{threat['boundary']}</p>
                    </div>
                    <div class="threat-section-card">
                        <h4>STRIDE Category:</h4>
                        <p>{threat['category']}</p>
                    </div>
                    <div class="threat-section-card">
                        <h4>Risk Assessment:</h4>
                        <p>Likelihood: {threat['likelihood']}/5 | Impact: {threat['impact']}/5</p>
                    </div>
                    <div class="mitigation-list">
                        <h4>Mitigation Controls:</h4>
                        <ul>
                            {mitigations_html}
                        </ul>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")

        # Detailed Threat and Mitigation Management (similar to old "Manage Threat Model" but streamlined)
        st.subheader("Detailed Threat & Mitigation Editor")
        
        # Create a unique list of all threats for selection
        all_threats_flat = []
        for boundary, data in st.session_state.threat_model.items():
            for threat in data['threats']:
                all_threats_flat.append({**threat, 'boundary': boundary})

        all_threat_names_for_editor = [f"{t['name']} ({t['boundary']})" for t in all_threats_flat]
        selected_threat_for_editor_display = st.selectbox(
            "Select a Threat to Edit Mitigations or Details",
            ["-- Select --"] + all_threat_names_for_editor,
            key="select_threat_for_editor"
        )

        if selected_threat_for_editor_display != "-- Select --":
            # Find the actual threat object
            selected_threat_name = selected_threat_for_editor_display.split(' (')[0]
            selected_threat_boundary = selected_threat_for_editor_display.split(' (')[1][:-1] # Remove closing parenthesis

            selected_threat_obj = None
            threat_idx_in_boundary = -1
            for idx, t in enumerate(st.session_state.threat_model[selected_threat_boundary]['threats']):
                if t['name'] == selected_threat_name:
                    selected_threat_obj = t
                    threat_idx_in_boundary = idx
                    break

            if selected_threat_obj:
                st.markdown(f"##### Editing: {selected_threat_obj['name']} in {selected_threat_boundary}")

                # Edit Threat Details
                with st.expander(f"✏️ Edit Threat Details for '{selected_threat_obj['name']}'"):
                    with st.form(f"edit_threat_details_form_{selected_threat_obj['id']}", clear_on_submit=False):
                        edited_threat_category = st.selectbox("STRIDE Category", ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'], index=['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'].index(selected_threat_obj['category']), key=f"edit_threat_cat_details_{selected_threat_obj['id']}")
                        edited_threat_likelihood = st.slider("Likelihood (1-5)", 1, 5, selected_threat_obj['likelihood'], key=f"edit_threat_lik_details_{selected_threat_obj['id']}")
                        edited_threat_impact = st.slider("Impact (1-5)", 1, 5, selected_threat_obj['impact'], key=f"edit_threat_imp_details_{selected_threat_obj['id']}")
                        
                        if st.form_submit_button("Save Threat Details"):
                            risk_score, risk_level = calculate_risk(edited_threat_likelihood, edited_threat_impact)
                            st.session_state.threat_model[selected_threat_boundary]['threats'][threat_idx_in_boundary].update({
                                'category': edited_threat_category,
                                'likelihood': edited_threat_likelihood,
                                'impact': edited_threat_impact,
                                'risk_score': risk_score,
                                'risk_level': risk_level
                            })
                            st.success(f"Threat details for '{selected_threat_obj['name']}' updated!")
                            st.rerun()

                # Manage Mitigations for this Threat
                st.markdown(f"###### Mitigations for '{selected_threat_obj['name']}'")
                
                with st.expander(f"➕ Add New Mitigation for '{selected_threat_obj['name']}'"):
                    with st.form(f"add_mitigation_form_{selected_threat_obj['id']}", clear_on_submit=True):
                        mitigation_type = st.selectbox("Mitigation Type", ["Preventive", "Detective", "Responsive"], key=f"new_mit_type_{selected_threat_obj['id']}")
                        mitigation_control = st.text_area("Control Description", key=f"new_mit_control_{selected_threat_obj['id']}")
                        
                        if st.form_submit_button("Add Mitigation"):
                            if mitigation_control:
                                new_mitigation_id = str(uuid.uuid4())
                                st.session_state.threat_model[selected_threat_boundary]['threats'][threat_idx_in_boundary]['mitigations'].append({
                                    'id': new_mitigation_id,
                                    'type': mitigation_type,
                                    'control': mitigation_control
                                })
                                st.success(f"Mitigation added for '{selected_threat_obj['name']}'!")
                                st.rerun()
                            else:
                                st.error("Control Description cannot be empty.")
                
                if selected_threat_obj['mitigations']:
                    st.markdown("Existing Mitigations:")
                    for j, mitigation in enumerate(selected_threat_obj['mitigations']):
                        with st.expander(f"🛡️ {mitigation['type']}: {mitigation['control'][:50]}..."):
                            with st.form(f"edit_mitigation_form_{mitigation['id']}", clear_on_submit=False):
                                edited_mitigation_type = st.selectbox("Mitigation Type", ["Preventive", "Detective", "Responsive"], index=["Preventive", "Detective", "Responsive"].index(mitigation['type']), key=f"edit_mit_type_{mitigation['id']}")
                                edited_mitigation_control = st.text_area("Control Description", value=mitigation['control'], key=f"edit_mit_control_{mitigation['id']}")
                                
                                col_buttons_mit = st.columns(2)
                                with col_buttons_mit[0]:
                                    if st.form_submit_button("Save Mitigation Changes"):
                                        st.session_state.threat_model[selected_threat_boundary]['threats'][threat_idx_in_boundary]['mitigations'][j].update({
                                            'type': edited_mitigation_type,
                                            'control': edited_mitigation_control
                                        })
                                        st.success("Mitigation updated!")
                                        st.rerun()
                                with col_buttons_mit[1]:
                                    if st.form_submit_button("Delete Mitigation"):
                                        st.session_state.threat_model[selected_threat_boundary]['threats'][threat_idx_in_boundary]['mitigations'].pop(j)
                                        st.success("Mitigation deleted!")
                                        st.rerun()
                else:
                    st.info("No mitigations added for this threat yet.")
        else:
            st.info("Select a threat above to manage its details and mitigations.")

def render_trust_boundary_details():
    st.subheader("🌐 Trust Boundary Details")
    st.write("Explore the security posture of each defined trust boundary, including associated threats, risks, and mitigations.")

    if not st.session_state.threat_model:
        st.info("No trust boundaries defined in the current threat model. Please define architecture components and connections first.")
        return

    for boundary_name, boundary_data in st.session_state.threat_model.items():
        with st.expander(f"### Trust Boundary: {boundary_name}"):
            st.markdown(f"**Description:** {boundary_data.get('description', 'No description provided.')}")
            
            # Display associated components (if any are explicitly linked in threat_model)
            if boundary_data.get('components'):
                st.markdown(f"**Associated Components:** {', '.join(boundary_data['components'])}")
            else:
                st.markdown("**Associated Components:** None explicitly linked in threat model data. (Refer to Architecture Diagram for context)")

            st.markdown("---")
            st.markdown("#### Threats within this Boundary:")

            if boundary_data['threats']:
                for threat in boundary_data['threats']:
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**Threat Name:** {threat['name']}")
                        st.markdown(f"**STRIDE Category:** {threat['category']}")
                        st.markdown(f"**Likelihood:** {threat['likelihood']}/5 | **Impact:** {threat['impact']}/5")
                    with col2:
                        risk_level_class = threat['risk_level'].lower()
                        st.markdown(f"<div class='risk-score-display {risk_level_class}'>{threat['risk_level'].upper()} ({threat['risk_score']})</div>", unsafe_allow_html=True)
                    
                    st.markdown("##### Mitigations:")
                    if threat['mitigations']:
                        for mitigation in threat['mitigations']:
                            st.markdown(f"- **{mitigation['type']}**: {mitigation['control']}")
                    else:
                        st.info("No mitigations defined for this threat.")
                    st.markdown("---") # Separator for threats within a boundary
            else:
                st.info("No threats defined for this trust boundary yet.")

def render_manage_saved_models():
    st.subheader("🗄️ Manage Saved Models")
    st.write("Save your current threat model or load a previously saved one.")

    # Save Current Model
    st.markdown("---")
    st.markdown("#### Save Current Threat Model")
    if st.session_state.user_id:
        with st.form("save_model_form"):
            model_name = st.text_input("Enter a name for your threat model (e.g., 'My Banking App v1')", key="save_model_name")
            save_button = st.form_submit_button("💾 Save Model")
            if save_button:
                if model_name:
                    # Call JS function to save to Firestore
                    # This is a simplified way; in a real app, you'd use a custom component
                    # that exposes a save method callable from Python.
                    # For now, we'll assume the JS part handles the actual Firestore interaction.
                    st.session_state.js_save_request = {
                        "model_name": model_name,
                        "architecture": st.session_state.architecture,
                        "threat_model": st.session_state.threat_model
                    }
                    st.success(f"Save request for '{model_name}' sent. Check console for JS logs.")
                    # Clear the request after sending
                    st.session_state.js_save_request = None
                else:
                    st.error("Please enter a name for the model.")
    else:
        st.info("Please wait for user authentication to save models.")

    # Load Saved Models
    st.markdown("---")
    st.markdown("#### Load Saved Threat Model")
    if st.session_state.user_id:
        # Hidden text area to receive loaded models data from JavaScript
        st.markdown(
            """
            <style>
            .stTextArea[data-testid="stTextArea-load-models"] {
                display: none;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
        load_models_data_transfer = st.text_area(
            "load_models_data",
            value=json.dumps([]), # Initial empty list
            height=68,
            key="streamlit_load_models_data", # This key is used by JS to send data
            help="Do not modify this field directly.",
        )

        # Trigger JS to load models when this section is visible
        st.session_state.js_load_request = True # Signal to JS to load models

        saved_models_list = []
        if load_models_data_transfer:
            try:
                loaded_models_raw = json.loads(load_models_data_transfer)
                saved_models_list = [{**m, 'display_name': f"{m['model_name']} (Last Updated: {datetime.fromisoformat(m['last_updated']).strftime('%Y-%m-%d %H:%M')})"} for m in loaded_models_raw]
            except json.JSONDecodeError:
                st.error("Error decoding loaded models data.")
        
        if saved_models_list:
            selected_model_display_name = st.selectbox(
                "Select a model to load:",
                ["-- Select a saved model --"] + [m['display_name'] for m in saved_models_list],
                key="load_model_select"
            )

            if selected_model_display_name != "-- Select a saved model --":
                selected_model_obj = next((m for m in saved_models_list if m['display_name'] == selected_model_display_name), None)
                if selected_model_obj:
                    col_load_buttons = st.columns(2)
                    with col_load_buttons[0]:
                        if st.button(f"📥 Load '{selected_model_obj['model_name']}'"):
                            st.session_state.architecture = selected_model_obj['architecture']
                            st.session_state.threat_model = selected_model_obj['threat_model']
                            st.session_state.show_report_sections = True
                            st.success(f"Model '{selected_model_obj['model_name']}' loaded successfully!")
                            st.rerun()
                    with col_load_buttons[1]:
                        if st.button(f"🗑️ Delete '{selected_model_obj['model_name']}'"):
                            # Trigger JS to delete from Firestore
                            st.session_state.js_delete_request = selected_model_obj['id']
                            st.info(f"Delete request for '{selected_model_obj['model_name']}' sent.")
                            st.session_state.js_delete_request = None # Clear request
                            st.rerun() # Rerun to refresh the list
                else:
                    st.error("Selected model not found.")
        else:
            st.info("No saved models found for this user.")
    else:
        st.info("Please wait for user authentication to load models.")

    # Reset the JS load request after processing
    st.session_state.js_load_request = False

    # Hidden text area for JS to send save/delete confirmations or trigger loads
    st.markdown(
        """
        <style>
        .stTextArea[data-testid="stTextArea-js-commands"] {
            display: none;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    js_commands_output = st.text_area(
        "js_commands_output",
        value="",
        height=68,
        key="streamlit_js_commands",
        help="Do not modify this field directly.",
    )

    # Process commands from JS
    if js_commands_output:
        try:
            command = json.loads(js_commands_output)
            if command.get("action") == "model_saved":
                st.success(f"Model '{command['model_name']}' successfully saved to cloud!")
                # Clear the text area to prevent re-processing
                st.session_state.streamlit_js_commands = ""
                st.rerun() # Rerun to refresh the UI
            elif command.get("action") == "model_deleted":
                st.success(f"Model '{command['model_id']}' successfully deleted from cloud!")
                st.session_state.streamlit_js_commands = ""
                st.rerun() # Rerun to refresh the UI
            elif command.get("action") == "load_models_response":
                # This is handled by load_models_data_transfer directly, but good for debugging
                pass
            elif command.get("action") == "error":
                st.error(f"JS Error: {command.get('message', 'Unknown error')}")
                st.session_state.streamlit_js_commands = ""
            # Clear the text area after processing
            st.session_state.streamlit_js_commands = ""
        except json.JSONDecodeError:
            st.error("Error decoding command from JS.")

    # Pass save/load/delete requests to JS
    js_request_data = {}
    if st.session_state.get('js_save_request'):
        js_request_data['save'] = st.session_state.js_save_request
    if st.session_state.get('js_load_request'):
        js_request_data['load'] = True
    if st.session_state.get('js_delete_request'):
        js_request_data['delete'] = st.session_state.js_delete_request

    # Hidden text area to send commands to JavaScript
    st.markdown(
        """
        <style>
        .stTextArea[data-testid="stTextArea-js-requests"] {
            display: none;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.text_area(
        "js_requests_input",
        value=json.dumps(js_request_data),
        height=68,
        key="streamlit_js_requests",
        help="Do not modify this field directly.",
    )


if __name__ == "__main__":
    main()
