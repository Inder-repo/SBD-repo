import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
import uuid # For generating unique IDs for new entries
import json # For passing data between Python and JavaScript

# Page configuration
st.set_page_config(
    page_title="Threat Model",
    page_icon="�",
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
        background: rgba(255, 255, 0.1);
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
    .risk-score-display.medium { background: #f1c40f; }
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
        height: 600px; /* Fixed height for the diagram */
    }
    #diagram-svg {
        width: 100%;
        height: 100%;
    }
    .diagram-node {
        cursor: pointer;
        stroke: #333;
        stroke-width: 2px;
        transition: all 0.2s ease-in-out;
    }
    .diagram-node:hover {
        transform: scale(1.05);
        stroke: #2a5298;
    }
    .diagram-node.selected {
        stroke: #667eea;
        stroke-width: 4px;
    }
    .diagram-node-text {
        font-family: sans-serif;
        font-size: 12px;
        fill: #333;
        pointer-events: none; /* Allows click to pass through to the circle */
        text-anchor: middle; /* Center text horizontally */
        dominant-baseline: central; /* Center text vertically */
    }
    .diagram-edge {
        stroke: #764ba2;
        stroke-width: 2px;
        fill: none;
        marker-end: url(#arrowhead);
    }
    .diagram-edge-label {
        font-family: sans-serif;
        font-size: 10px;
        fill: #555;
        background-color: rgba(255,255,255,0.7);
        padding: 2px 5px;
        border-radius: 3px;
    }
    .diagram-controls {
        position: absolute;
        top: 10px;
        left: 10px;
        z-index: 10;
        display: flex;
        gap: 10px;
    }
    .diagram-controls button {
        background-color: #2a5298;
        color: white;
        border: none;
        padding: 8px 15px;
        border-radius: 5px;
        cursor: pointer;
        font-size: 14px;
        transition: background-color 0.2s ease;
    }
    .diagram-controls button:hover {
        background-color: #1e3c72;
    }
    .diagram-controls button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
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
        background-color: rgba(0,0,0,0.4);
        justify-content: center;
        align-items: center;
    }
    .modal-content {
        background-color: #fefefe;
        margin: auto;
        padding: 20px;
        border-radius: 10px;
        width: 80%;
        max-width: 500px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        display: flex;
        flex-direction: column;
        gap: 15px;
    }
    .modal-content input, .modal-content select, .modal-content textarea {
        width: calc(100% - 20px);
        padding: 10px;
        margin-top: 5px;
        border: 1px solid #ddd;
        border-radius: 5px;
    }
    .modal-content button {
        background-color: #28a745;
        color: white;
        padding: 10px 20px;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        align-self: flex-end;
    }
    .modal-content button.cancel {
        background-color: #dc3545;
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
        # Initial boundaries can be empty or pre-populated if desired
    }

# Initialize session state for threat data
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = get_initial_threat_data()

# Initialize session state for architecture data
if 'architecture' not in st.session_state:
    st.session_state.architecture = {
        'components': [],
        'connections': []
    }

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
    
    # Reset button
    if st.sidebar.button("🔄 Reset All Data"):
        st.session_state.threat_model = get_initial_threat_data()
        st.session_state.architecture = {'components': [], 'connections': []}
        st.rerun()
        st.success("Threat model and architecture data reset!")

    # --- Architecture Definition Section ---
    st.subheader("🏗️ 1. Define System Architecture")
    st.write("Interact with the diagram below to add components and define data flows. Changes will automatically update your threat model.")

    # HTML/JS for the interactive diagram
    # This script handles adding nodes/edges and sending data back to Streamlit
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
            }}
            #diagram-svg {{
                width: 100%;
                height: 100%;
            }}
            .diagram-node {{
                cursor: pointer;
                stroke: #333;
                stroke-width: 2px;
                transition: all 0.2s ease-in-out;
            }}
            .diagram-node:hover {{
                transform: scale(1.05);
                stroke: #2a5298;
            }}
            .diagram-node.selected {{
                stroke: #667eea;
                stroke-width: 4px;
            }}
            .diagram-node-text {{
                font-family: sans-serif;
                font-size: 12px;
                fill: #333;
                pointer-events: none;
                text-anchor: middle;
                dominant-baseline: central;
            }}
            .diagram-edge {{
                stroke: #764ba2;
                stroke-width: 2px;
                fill: none;
                marker-end: url(#arrowhead);
            }}
            .diagram-edge-label {{
                font-family: sans-serif;
                font-size: 10px;
                fill: #555;
                background-color: rgba(255,255,255,0.7);
                padding: 2px 5px;
                border-radius: 3px;
            }}
            .diagram-controls {{
                position: absolute;
                top: 10px;
                left: 10px;
                z-index: 10;
                display: flex;
                flex-direction: column; /* Stack buttons vertically */
                gap: 10px;
            }}
            .diagram-controls button {{
                background-color: #2a5298;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
                transition: background-color 0.2s ease;
            }}
            .diagram-controls button:hover {{
                background-color: #1e3c72;
            }}
            .diagram-controls button:disabled {{
                background-color: #cccccc;
                cursor: not-allowed;
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
                background-color: rgba(0,0,0,0.4);
                justify-content: center;
                align-items: center;
            }}
            .modal-content {{
                background-color: #fefefe;
                margin: auto;
                padding: 20px;
                border-radius: 10px;
                width: 80%;
                max-width: 500px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.3);
                display: flex;
                flex-direction: column;
                gap: 15px;
            }}
            .modal-content input, .modal-content select, .modal-content textarea {{
                width: calc(100% - 20px);
                padding: 10px;
                margin-top: 5px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }}
            .modal-content button {{
                background-color: #28a745;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                align-self: flex-end;
            }}
            .modal-content button.cancel {{
                background-color: #dc3545;
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
                <input type="text" id="connTrustBoundary">
                <div style="display: flex; justify-content: space-between;">
                    <button type="button" class="cancel" onclick="closeModal('addConnectionModal')">Cancel</button>
                    <button type="button" onclick="saveConnection()">Add Connection</button>
                </div>
            </div>
        </div>

        <script>
            const streamlitReport = window.parent.document.querySelector('.stApp [data-testid="stVerticalBlock"]');
            const svg = document.getElementById('diagram-svg');
            let nodes = {json.dumps(st.session_state.architecture['components'])};
            let connections = {json.dumps(st.session_state.architecture['connections'])};
            let selectedNode = null;

            // Function to send data back to Streamlit
            function sendDataToStreamlit() {{
                const data = {{
                    nodes: nodes,
                    connections: connections
                }};
                // Use a hidden text area to send data back to Streamlit
                // Streamlit will pick this up on rerun
                const outputElement = window.parent.document.getElementById('streamlit_output_data');
                if (outputElement) {{
                    outputElement.value = JSON.stringify(data);
                    outputElement.dispatchEvent(new Event('input')); // Trigger Streamlit rerun
                }} else {{
                    console.error("Streamlit output element not found.");
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
                
                // Draw nodes
                nodes.forEach(node => {{
                    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    circle.setAttribute('cx', node.x);
                    circle.setAttribute('cy', node.y);
                    circle.setAttribute('r', 30);
                    // Corrected line: Escaping inner curly braces for Python's f-string
                    circle.setAttribute('class', `diagram-node ${{selectedNode && selectedNode.id === node.id ? 'selected' : ''}}`);
                    circle.setAttribute('fill', getNodeColor(node.type));
                    circle.dataset.nodeId = node.id;
                    circle.addEventListener('click', (event) => {{
                        event.stopPropagation(); // Prevent SVG click
                        selectNode(node.id);
                    }});
                    svg.appendChild(circle);

                    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    text.setAttribute('x', node.x);
                    text.setAttribute('y', node.y);
                    text.setAttribute('class', 'diagram-node-text');
                    text.textContent = node.name;
                    svg.appendChild(text);
                }});

                // Draw connections
                connections.forEach(conn => {{
                    const sourceNode = nodes.find(n => n.id === conn.source_id);
                    const targetNode = nodes.find(n => n.id === conn.target_id);

                    if (sourceNode && targetNode) {{
                        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                        line.setAttribute('x1', sourceNode.x);
                        line.setAttribute('y1', sourceNode.y);
                        line.setAttribute('x2', targetNode.x);
                        line.setAttribute('y2', targetNode.y);
                        line.setAttribute('class', 'diagram-edge');
                        svg.appendChild(line);

                        // Add label for the edge
                        const midX = (sourceNode.x + targetNode.x) / 2;
                        const midY = (sourceNode.y + targetNode.y) / 2;
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

            function getNodeColor(type) {{
                switch(type) {{
                    case 'User': return '#ff6b6b'; // external
                    case 'Web Server':
                    case 'Load Balancer':
                    case 'Firewall': return '#4ecdc4'; // security/presentation
                    case 'Application Server': return '#96ceb4'; // application
                    case 'Database':
                    case 'Core Banking System': return '#ffeaa7'; // data
                    case 'API Gateway':
                    case 'Authentication Service': return '#45b7d1'; // presentation/security
                    case 'External Service': return '#fd79a8'; // integration
                    default: return 'lightgray'; // other
                }}
            }}

            function selectNode(nodeId) {{
                nodes.forEach(node => {{
                    // Corrected line: Escaping inner curly braces for Python's f-string
                    const element = svg.querySelector(`circle[data-node-id="${{node.id}}"]`);
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
                document.getElementById('connTrustBoundary').value = '';
                openModal('addConnectionModal');
            }});

            function saveConnection() {{
                const sourceId = document.getElementById('connSource').value;
                const targetId = document.getElementById('connTarget').value;
                const dataFlow = document.getElementById('connDataFlow').value;
                const description = document.getElementById('connDescription').value;
                const trustBoundary = document.getElementById('connTrustBoundary').value;

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
    # We use a hidden text_area to receive data back from the JS
    st.components.v1.html(diagram_html, height=600, scrolling=False)

    # Hidden text area to receive data from JavaScript
    # Streamlit will re-run the script when this value changes
    architecture_data_json = st.text_area("architecture_data_transfer", value=json.dumps(st.session_state.architecture), height=1, key="streamlit_output_data", help="Do not modify this field directly.", disabled=True)

    # Process data received from JavaScript
    if architecture_data_json:
        try:
            updated_architecture = json.loads(architecture_data_json)
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
                st.rerun() # Rerun to update the Python state and subsequent sections
        except json.JSONDecodeError:
            st.error("Error decoding architecture data from diagram.")
    
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
                if 'Phishing Attacks' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Phishing Attacks', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'DDoS Attacks' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'DDoS Attacks', 'category': 'Denial of Service', 'likelihood': 3, 'impact': 4, 'boundary': conn['trust_boundary_crossing']})
                if 'SQL Injection' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'SQL Injection', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'Cross-Site Scripting (XSS)' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Cross-Site Scripting (XSS)', 'category': 'Tampering', 'likelihood': 3, 'impact': 4, 'boundary': conn['trust_boundary_crossing']})

            # Rule 2: Application to Database
            if source_comp['type'] == 'Application Server' and target_comp['type'] == 'Database':
                if 'Database Injection' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Database Injection', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'Data Exfiltration' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Data Exfiltration', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'Unauthorized Data Access' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Unauthorized Data Access', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})

            # Rule 3: Connections crossing "Internal" boundaries (simplified)
            if "internal" in conn['trust_boundary_crossing'].lower():
                if 'Lateral Movement' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Lateral Movement', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'Internal Service Spoofing' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Internal Service Spoofing', 'category': 'Spoofing', 'likelihood': 2, 'impact': 4, 'boundary': conn['trust_boundary_crossing']})

            # Rule 4: External Integrations
            if target_comp['type'] == 'External Service' or source_comp['type'] == 'External Service':
                if 'API Key Exposure' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'API Key Exposure', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 4, 'boundary': conn['trust_boundary_crossing']})
                if 'Data Sharing Violation' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Data Sharing Violation', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 4, 'boundary': conn['trust_boundary_crossing']})

            # Rule 5: Authentication Services
            if target_comp['type'] == 'Authentication Service':
                if 'Authentication Bypass' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Authentication Bypass', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'Credential Stuffing' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Credential Stuffing', 'category': 'Elevation of Privilege', 'likelihood': 3, 'impact': 4, 'boundary': conn['trust_boundary_crossing']})

            # Rule 6: Core Banking System
            if target_comp['type'] == 'Core Banking System':
                if 'Financial Fraud' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Financial Fraud', 'category': 'Tampering', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})
                if 'Transaction Manipulation' not in [t['name'] for b in st.session_state.threat_model.values() for t in b['threats']]:
                    suggested_threats.append({'name': 'Transaction Manipulation', 'category': 'Tampering', 'likelihood': 2, 'impact': 5, 'boundary': conn['trust_boundary_crossing']})

    if suggested_threats:
        df_suggested_threats = pd.DataFrame(suggested_threats)
        df_suggested_threats['risk_score'], df_suggested_threats['risk_level'] = zip(*df_suggested_threats.apply(lambda row: calculate_risk(row['likelihood'], row['impact']), axis=1))
        
        st.dataframe(df_suggested_threats[['name', 'category', 'likelihood', 'impact', 'risk_score', 'risk_level', 'boundary']], use_container_width=True)

        st.markdown("---")
        st.subheader("Add Selected Suggested Threats to Threat Model")
        
        threat_names_to_add = st.multiselect(
            "Select threats to add to your main threat model:",
            [t['name'] for t in suggested_threats],
            key="select_threats_to_add"
        )

        if st.button("Add Selected Threats"):
            added_count = 0
            for threat_name in threat_names_to_add:
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
                            'risk_score': threat_to_add['risk_score'],
                            'risk_level': threat_to_add['risk_level'],
                            'mitigations': []
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
                        {''.join([f'<li>{m["type"]}: {m["control"]}</li>' for m in threat['mitigations']]) if threat['mitigations'] else '<li>No mitigations defined yet.</li>'}
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

if __name__ == "__main__":
    main()
