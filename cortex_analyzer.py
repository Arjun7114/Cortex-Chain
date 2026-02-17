import boto3
import json
import os
import ollama
from dotenv import load_dotenv

# --- 🔐 SECURE CONFIGURATION ---
load_dotenv()

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")      
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")  
BUCKET_NAME = "cortex-chain-logs-arjun" 
REGION = "ap-south-1"  

# --- CONNECT TO AWS S3 ---
s3 = boto3.client(
    's3',
    region_name=REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

def analyze_logs():
    print("--- 🧠 CORTEX-CHAIN AI ANALYZER ---")
    print(f"Fetching logs from AWS S3 ({BUCKET_NAME})...\n")

    try:
        # 1. Get the list of logs from S3
        response = s3.list_objects_v2(Bucket=BUCKET_NAME)
        
        if 'Contents' not in response:
            print("No logs found in the bucket. Run the generator script first!")
            return

        # 2. Grab the very first log file we find
        log_file_key = response['Contents'][0]['Key']
        print(f"📥 Downloading Log: {log_file_key}")

        # 3. Read the log content
        log_obj = s3.get_object(Bucket=BUCKET_NAME, Key=log_file_key)
        log_content = log_obj['Body'].read().decode('utf-8')
        
        print(f"🔍 Log Data: {log_content}\n")
        print("🤖 Llama 3 is analyzing the threat. Please wait...\n")

        # 4. Ask our Local AI to analyze the log
        prompt = f"""
        You are a Senior SOC Analyst at a Big Four firm.
        Review this network log: {log_content}
        
        Provide a concise analysis in 3 bullet points:
        1. Is this a threat? (Yes/No and Why)
        2. What is the severity?
        3. What is the immediate recommended action?
        """

        # 5. Get the response from local Llama 3
        ai_response = ollama.generate(model='llama3', prompt=prompt)
        
        print("========================================")
        print("🚨 AI VERDICT & INCIDENT RESPONSE PLAN")
        print("========================================")
        print(ai_response['response'])
        print("========================================\n")

    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    analyze_logs()