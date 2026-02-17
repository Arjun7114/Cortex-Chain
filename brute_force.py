import subprocess
import time

print("💀 Initiating Simulated Brute Force Attack...")

for i in range(2):
    print(f"Attempt {i+1}: Trying fake credentials...")
    # This harmlessly attempts to connect to your local C drive with a fake password
    subprocess.run(["net", "use", r"\\127.0.0.1\C$", "/user:FakeHacker", "BadPassword123!"], capture_output=True)
    time.sleep(1)

print("🎯 Attack simulation complete. Windows Event 4625 should now be generated.")