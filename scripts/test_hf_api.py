from huggingface_hub import InferenceClient
from dotenv import load_dotenv
import os

load_dotenv()

token = os.getenv("HF_TOKEN")

if not token:
    print("❌ HF_TOKEN not found in .env")
    exit(1)

print("✅ Token loaded")

client = InferenceClient(
    model="Qwen/Qwen2.5-Coder-7B-Instruct",
    token=token
)

response = client.chat_completion(
    messages=[{
        "role": "user",
        "content": "What is SQL injection in 1 sentence?"
    }],
    max_tokens=100
)

print("✅ API call successful!")
print(f"\nResponse:\n{response.choices[0].message.content}")
