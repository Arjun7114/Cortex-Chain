import boto3
import json
import random
import time
import os
from datetime import datetime
from dotenv import load_dotenv

# --- 🔐 SECURE CONFIGURATION ---
# This line unlocks the hidden .env file and loads your keys safely into memory
load_dotenv()

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")      
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")  

BUCKET_NAME = "cortex-chain-logs-arjun" 
REGION = "ap-south-1"  

# --- CONNECT TO AWS ---
s3 = boto3.client(
    's3',
    region_name=REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

def generate_log():
    """Generates a random cyber event."""
    attack_types = ["Brute Force", "SQL Injection", "DDoS", "Malware Download"]
    is_attack = random.random() < 0.3  

    log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": f"192.168.1.{random.randint(1, 255)}",
        "user_id": f"user_{random.randint(100, 999)}",
        "destination": "server-finance-01",
    }

    if is_attack:
        log["event_type"] = "SECURITY_ALERT"
        log["severity"] = "HIGH"
        log["threat"] = random.choice(attack_types)
        log["action_required"] = True
        log["message"] = "Suspicious activity detected."
    else:
        log["event_type"] = "Traffic"
        log["severity"] = "LOW"
        log["message"] = "Authorized access."

    return log

def start_upload():
    print(f"--- 🚀 CORTEX-CHAIN: SECURELY CONNECTING TO {BUCKET_NAME} ---")
    print("Press Ctrl+C to stop the simulation.\n")
    
    try:
        while True:
            data = generate_log()
            file_name = f"log_{int(time.time())}_{random.randint(1000,9999)}.json"
            
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=file_name,
                Body=json.dumps(data),
                ContentType='application/json'
            )
            
            if data.get('severity') == "HIGH":
                print(f"🔥 [ATTACK] Uploaded: {file_name} -> {data['threat']}")
            else:
                print(f"✅ [NORMAL] Uploaded: {file_name}")

            time.sleep(random.uniform(1, 3))

    except KeyboardInterrupt:
        print("\n🛑 Simulation Stopped.")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    start_upload()