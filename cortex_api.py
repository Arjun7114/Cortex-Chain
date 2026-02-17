from fastapi import FastAPI, Request
import ollama
import json
import boto3
import hashlib
from datetime import datetime

app = FastAPI(title="Cortex-Chain AI Brain", version="3.0")

# --- Configuration ---
S3_BUCKET_NAME = "cortex-chain-logs-arjun"
# Note: This uses your 'cortex-bot' credentials from 'aws configure'
s3_client = boto3.client('s3')

def generate_log_hash(data):
    """Creates a SHA-256 Digital Fingerprint for the Blockchain ledger."""
    log_string = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(log_string).hexdigest()

def upload_to_s3(data, filename):
    """Archives the compliance package to the AWS Cloud."""
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=f"alerts/{filename}",
            Body=json.dumps(data, indent=2),
            ContentType='application/json'
        )
        print(f"☁️ [AWS S3] Successfully archived to {S3_BUCKET_NAME}")
    except Exception as e:
        print(f"❌ AWS Upload Error: {e}")

@app.post("/analyze-threat")
async def analyze_threat(request: Request):
    # Receive payload from Splunk
    splunk_payload = await request.json()
    threat_data = splunk_payload.get("result", splunk_payload)
    
    print(f"\n🚨 [INCOMING ALERT FROM SPLUNK] 🚨")
    
    prompt = f"Analyze this log for brute force. Be concise: {json.dumps(threat_data)}"

    try:
        # 1. Get AI Verdict (Llama 3 thinking...)
        ai_response = ollama.generate(model='llama3', prompt=prompt)
        verdict = ai_response['response']
        print(f"🧠 [AI VERDICT]\n{verdict}")

        # 2. Generate Blockchain Hash (The Notary)
        log_hash = generate_log_hash(threat_data)
        
        # 3. Create Compliance Package (Ensures AI text is included!)
        compliance_package = {
            "timestamp": datetime.now().isoformat(),
            "analyst_id": "arjun-soc-intern",
            "log_hash": log_hash,
            "ai_analysis": verdict,
            "raw_log": threat_data
        }

        # 4. Upload to AWS S3 (Indented correctly inside try block)
        file_name = f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        upload_to_s3(compliance_package, file_name)
        
        print(f"🔗 [BLOCKCHAIN] Log Hash Generated: {log_hash}")
        
        return {
            "status": "success", 
            "hash": log_hash, 
            "s3_file": file_name,
            "verdict": "Archived to Cloud"
        }

    except Exception as e:
        print(f"❌ Error in Pipeline: {e}")
        return {"status": "error", "message": str(e)}