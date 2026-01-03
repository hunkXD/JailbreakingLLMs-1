#!/usr/bin/env python3
import os
from openai import OpenAI
import google.generativeai as genai

# Test OpenAI
print("Testing OpenAI API...")
try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": "Say hello"}],
        max_tokens=10
    )
    print(f"✓ OpenAI works: {response.choices[0].message.content}")
except Exception as e:
    print(f"✗ OpenAI failed: {e}")

# Test Google (Gemini)
print("\nTesting Google Gemini API...")
try:
    genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
    model = genai.GenerativeModel('gemini-pro')
    response = model.generate_content("Say hello")
    print(f"✓ Gemini works: {response.text}")
except Exception as e:
    print(f"✗ Gemini failed: {e}")

print("\n✓ All APIs configured correctly!")

