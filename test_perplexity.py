import os
import requests

api_key = os.environ.get('PERPLEXITYAI_API_KEY')
if not api_key:
    print("ERROR: PERPLEXITYAI_API_KEY not set")
    exit(1)

print("Testing Perplexity API...")

response = requests.post(
    "https://api.perplexity.ai/chat/completions",
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    },
    json={
        "model": "sonar",
        "messages": [
            {"role": "user", "content": "Say hello in one word"}
        ]
    }
)

if response.status_code == 200:
    print("✓ Perplexity API works!")
    print(f"Response: {response.json()['choices'][0]['message']['content']}")
else:
    print(f"✗ Error: {response.status_code}")
    print(response.text)
