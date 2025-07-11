import streamlit as st
import pandas as pd

# Try to import streamlit-flow (React Flow wrapper)
try:
    from streamlit_flow import flow
except ImportError:
    st.error("Please install streamlit-flow: pip install streamlit-flow")
    st.stop()

# --- STRIDE Threat Model ---
STRIDE_THREATS = {
    "Spoofing": "Impersonation of users or components.",
    "Tampering": "Unauthorized modification of data.",
    "Repudiation": "Actions that cannot be traced to an entity.",
    "Information Disclosure": "Exposure of sensitive data.",
    "Denial of Service": "Disruption of service availability.",
    "Elevation of Privilege": "Unauthorized privilege gain."
}
THREAT_MITIGATIONS = {
    "Spoofing": "Use strong authentication (MFA, certificates).",
    "Tampering": "Apply input validation, integrity checks, and secure protocols.",
    "Repudiation": "Enable logging and audit trails.",
    "Information Disclosure": "Encrypt data in transit and at rest.",
    "Denial of Service": "Implement rate limiting and redundancy.",
    "Elevation of Privilege": "Enforce least privilege and secure configuration."
}

# --- Sample Model ---
SAMPLES = {
    "Online Banking": {
        "nodes": [
            {"id": "user", "type": "input", "data": {"label": "User"}, "position": {"x": 100, "y": 100}},
            {"id": "web", "data": {"label": "Web App"}, "position": {"x": 300, "y": 100}},
            {"id": "api", "data": {"label": "API Gateway"}, "position": {"x": 500, "y": 100}},
            {"id": "db", "type": "output", "data": {"label": "Database"}, "position": {"x": 700, "y": 100}},
            {"id": "pay", "data": {"label": "Payment Processor"}, "position": {"x": 500, "y": 250}},
            {"id": "dmz", "type": "group", "data": {"label": "DMZ"}, "position": {"x": 250, "y": 60}, "style": {"width": 300, "height": 120, "backgroundColor": "#e0e0e0"}},
        ],
        "edges": [
            {"id": "e1", "source": "user", "target": "web"},
            {"id": "e2", "source": "web", "target": "api"},
            {"id": "e3", "source": "api", "target": "db"},
            {"id": "e4", "source": "web", "target": "pay"},
        ]
    },
    "Online Order Processing": {
        "nodes": [
            {"id": "user", "type": "input", "data": {"label": "User"}, "position": {"x": 100, "y": 100}},
            {"id": "mobile", "data": {"label": "Mobile App"}, "position": {"x": 300, "y": 100}},
            {"id": "api", "data": {"label": "API Gateway"}, "position": {"x": 500, "y": 100}},
            {"id": "db", "type": "output", "data": {"label": "Database"}, "position": {"x": 700, "y": 100}},
            {"id": "ext", "data": {"label": "External Service"}, "position": {"x": 500, "y": 250}},
            {"id": "dmz", "type": "group", "data": {"label": "DMZ"}, "position": {"x": 250, "y": 60}, "style": {"width": 300, "height": 120, "backgroundColor": "#e0e0e0"}},
        ],
        "edges": [
            {"id": "e1", "source": "user", "target": "mobile"},
            {"id": "e2", "source": "mobile", "target": "api"},
            {"id": "e3", "source": "api", "target": "db"},
            {"id": "e4", "source": "api", "target": "ext"},
        ]
    }
}

# --- App Layout ---
st.set_page_config(page_title="Diagram-Driven Threat Modeling", layout="wide")
st.title("Enterprise Threat Modeling via Interactive Diagram")

st.markdown("""
Build your architecture visually below.  
- **Add Node:** Double-click canvas or use the "+" button.  
- **Connect Nodes:** Drag from one node's handle to another.  
- **Edit Node:** Click a node to rename (e.g., 'Web App', 'DB', 'DMZ').  
- **Group Nodes:** Use group/label nodes to represent trust boundaries (e.g., 'DMZ', 'Internal').  
- **Delete:** Select node/edge and press delete key.
""")

with st.sidebar:
    st.header("Sample Models")
    sample_choice = st.selectbox("Load a sample architecture", ["(None)"] + list(SAMPLES.keys()))
    if sample_choice != "(None)":
        st.session_state.diagram = {
            "nodes": SAMPLES[sample_choice]["nodes"],
            "edges": SAMPLES[sample_choice]["edges"]
        }
        st.success(f"Loaded sample: {sample_choice}")

    if st.button("Clear Diagram"):
        st.session_state.diagram = {
            "nodes": [],
            "edges": []
        }
        st.success("Diagram cleared.")

# --- Initial Diagram (if not loaded from sample) ---
if "diagram" not in st.session_state:
    st.session_state.diagram = {
        "nodes": [
            {"id": "user", "type": "input", "data": {"label": "User"}, "position": {"x": 100, "y": 100}},
            {"id": "web", "data": {"label": "Web App"}, "position": {"x": 300, "y": 100}},
            {"id": "api", "data": {"label": "API Gateway"}, "position": {"x": 500, "y": 100}},
            {"id": "db", "type": "output", "data": {"label": "Database"}, "position": {"x": 700, "y": 100}},
            {"id": "dmz", "type": "group", "data": {"label": "DMZ"}, "position": {"x": 250, "y": 60}, "style": {"width": 300, "height": 120, "backgroundColor": "#e0e0e0"}},
        ],
        "edges": [
            {"id": "e1", "source": "user", "target": "web"},
            {"id": "e2", "source": "web", "target": "api"},
            {"id": "e3", "source": "api", "target": "db"},
        ]
    }

diagram = flow(
    nodes=st.session_state.diagram["nodes"],
    edges=st.session_state.diagram["edges"],
    height=500,
    width="100%",
    editable=True,
    fit_view=True,
    show_controls=True,
    show_mini_map=True,
    show_background=True,
    snap_to_grid=True,
    return_on_change=True,
)

if diagram:
    st.session_state.diagram = diagram

nodes = st.session_state.diagram["nodes"]
edges = st.session_state.diagram["edges"]

# --- Extraction Logic ---
components = [
    {
        "id": n["id"],
        "name": n["data"]["label"],
        "type": n.get("type", "process"),
        "x": n["position"]["x"],
        "y": n["position"]["y"]
    }
    for n in nodes if n.get("type") not in ("group", "label")
]
trust_boundaries = [
    {
        "id": n["id"],
        "name": n["data"]["label"],
        "type": n.get("type", "group"),
        "x": n["position"]["x"],
        "y": n["position"]["y"]
    }
    for n in nodes if n.get("type") in ("group", "label")
]
data_flows = [
    {
        "id": e["id"],
        "source": next((n["data"]["label"] for n in nodes if n["id"] == e["source"]), e["source"]),
        "target": next((n["data"]["label"] for n in nodes if n["id"] == e["target"]), e["target"]),
    }
    for e in edges
]

st.header("📦 Extracted Components")
st.dataframe(pd.DataFrame(components), use_container_width=True)

st.header("🔗 Extracted Data Flows")
st.dataframe(pd.DataFrame(data_flows), use_container_width=True)

st.header("🛡️ Extracted Trust Boundaries")
st.dataframe(pd.DataFrame(trust_boundaries), use_container_width=True)

# --- STRIDE Threat Analysis ---
def stride_analysis(source, target, boundary=None):
    threats = []
    for threat, desc in STRIDE_THREATS.items():
        threats.append({
            "Source": source,
            "Target": target,
            "Trust Boundary": boundary if boundary else "",
            "Threat": threat,
            "Description": desc,
            "Mitigation": THREAT_MITIGATIONS[threat]
        })
    return threats

st.header("🛡️ STRIDE Threat Analysis")

if data_flows:
    all_threats = []
    for flow in data_flows:
        # Try to infer boundary by checking if source or target is inside a group node (advanced: not implemented here)
        boundary = ""
        all_threats.extend(stride_analysis(flow["source"], flow["target"], boundary))
    threats_df = pd.DataFrame(all_threats)
    st.dataframe(threats_df, use_container_width=True)

    # Export functionality
    st.download_button(
        label="Export Threat Model (CSV)",
        data=threats_df.to_csv(index=False),
        file_name="threat_model.csv",
        mime="text/csv"
    )
else:
    st.info("Draw at least one data flow to generate threats.")

st.markdown("---")
st.info("You can use this app to visually model your architecture, extract all components, flows, and boundaries, and perform automated STRIDE threat analysis. Export your threat model for further documentation or review.")
