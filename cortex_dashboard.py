import streamlit as st
import json
import pandas as pd

# --- UI CONFIGURATION ---
st.set_page_config(
    page_title="Cortex-Chain SOC", 
    page_icon="🛡️", 
    layout="wide"
)

# --- HEADER ---
st.title("🛡️ Cortex-Chain: AI SOC Dashboard")
st.markdown("*Enterprise Threat Intelligence powered by Local Llama 3 & Cryptographic Ledgers*")
st.divider()

def load_ledger():
    try:
        with open("secure_ledger.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

ledger_data = load_ledger()

if ledger_data:
    # --- METRICS ROW ---
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs Secured", len(ledger_data))
    col2.metric("Encryption Standard", "SHA-256")
    col3.metric("Network Status", "🟢 Active & Immutable")
    
    st.divider()

    # --- BLOCKCHAIN VISUALIZER ---
    st.subheader("⛓️ Immutable Audit Trail (Live Blockchain)")
    
    # Format the data for a beautiful table
    df = pd.DataFrame(ledger_data)
    
    # Reorder columns for better reading
    df = df[['timestamp', 'file_name', 'previous_hash', 'current_hash']]
    
    # Display the interactive table
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    
    # --- LATEST EVENT FOCUS ---
    st.subheader("🚨 Most Recent Security Event")
    latest_event = ledger_data[-1]
    
    st.info(f"**Target File:** {latest_event['file_name']}")
    st.code(f"Previous Block Hash : {latest_event['previous_hash']}\n"
            f"Current Block Hash  : {latest_event['current_hash']}", language="bash")
    
else:
    st.warning("⚠️ No secure_ledger.json found. Please run the Blockchain engine first.")