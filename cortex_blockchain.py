import boto3
import json
import os
import hashlib
from datetime import datetime
from dotenv import load_dotenv

# --- 🔐 SECURE CONFIGURATION ---
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

def calculate_hash(data, previous_hash):
    """Creates a SHA-256 digital fingerprint (The Hash)."""
    # We combine the log's data WITH the previous file's fingerprint
    string_to_hash = f"{data}{previous_hash}"
    return hashlib.sha256(string_to_hash.encode()).hexdigest()

def build_blockchain():
    print("--- ⛓️ CORTEX-CHAIN: SECURE LEDGER GENERATION ---")
    print(f"Scanning S3 Data Lake ({BUCKET_NAME}) for logs...\n")

    try:
        response = s3.list_objects_v2(Bucket=BUCKET_NAME)
        if 'Contents' not in response:
            print("No logs found in the bucket!")
            return

        # Sort logs by creation time so the chain flows chronologically
        logs = sorted(response['Contents'], key=lambda x: x['LastModified'])
        
        blockchain = []
        # The Genesis Hash (The starting point of the chain)
        previous_hash = "0000000000000000000000000000000000000000000000000000000000000000" 

        for log in logs:
            log_key = log['Key']
            print(f"🔒 Securing: {log_key}")

            # 1. Read the file from AWS S3
            log_obj = s3.get_object(Bucket=BUCKET_NAME, Key=log_key)
            log_content = log_obj['Body'].read().decode('utf-8')

            # 2. Create the cryptographic hash
            current_hash = calculate_hash(log_content, previous_hash)

            # 3. Add it to our Ledger
            block = {
                "file_name": log_key,
                "previous_hash": previous_hash,
                "current_hash": current_hash,
                "timestamp": str(datetime.now())
            }
            blockchain.append(block)
            
            # 4. The current hash becomes the previous hash for the next file!
            previous_hash = current_hash

        # 5. Save the immutable ledger locally
        with open("secure_ledger.json", "w") as f:
            json.dump(blockchain, f, indent=4)

        print("\n=================================================")
        print("✅ BLOCKCHAIN LEDGER SUCCESSFULLY CREATED!")
        print("Saved as 'secure_ledger.json' in your workspace.")
        print("=================================================")

    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    build_blockchain()