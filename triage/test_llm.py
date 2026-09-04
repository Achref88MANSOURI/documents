from gradio_client import Client

COLAB_URL = "https://a96f30f559f5b73827.gradio.live"

print("Connecting to Colab GPU...")
client = Client(COLAB_URL)

test_prompt = """
You are a SOC analyst. 
Analyze this log: User 'admin' failed login 50 times in 2 minutes from IP 192.168.1.100. 
What is the attack type and your immediate action?
"""

print("Sending request to model...\n")

# Call the API simply by passing the prompt
result = client.predict(test_prompt)

print("--- Model Response ---")
print(result)
