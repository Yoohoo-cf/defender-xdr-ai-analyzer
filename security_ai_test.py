import requests
import json

alert = {
    "device": "vm-ai-sec-linux-01",
    "severity": "High",
    "title": "Suspicious SSH activity",
    "description": "Multiple failed SSH login attempts were detected from the same source IP."
}

prompt = f"""
You are a security analyst.

Analyze this security alert:

{json.dumps(alert, indent=2)}

Return:
1. Summary
2. Possible threat
3. Risk level
4. Investigation steps
5. Recommended containment actions
"""

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": "llama3.2:3b",
        "prompt": prompt,
        "stream": False
    },
    timeout=120
)

response.raise_for_status()

result = response.json()

print(result["response"])
