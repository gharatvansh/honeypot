"""Test the stateless recovery of conversation IDs."""
import uuid
from src.conversation_manager import conversation_manager

print("="*60)
print("Testing Conversation ID Recovery")
print("="*60)

# Step 1: Start a conversation
print("\nStep 1: Starting new conversation...")
result1 = conversation_manager.start_conversation("Hello scammer")
conv_id = result1["conversation_id"]
print(f"  Created ID: {conv_id}")

# Step 2: "Crash" the server (clear memory)
print("\nStep 2: Clearing server memory (simulating restart)...")
conversation_manager.conversations = {}
print("  Memory cleared. Conversation should be gone.")

# Verify it's gone
if not conversation_manager.get_conversation(conv_id):
    print("  Verified: Conversation not found in memory.")
else:
    print("  ERROR: Conversation still exists!")

# Step 3: Try to continue with the OLD ID (simulating main.py logic)
print("\nStep 3: Attempting to continue with OLD ID...")
message = "I am still here"
persona_type = None

# Logic from main.py
result2 = conversation_manager.continue_conversation(conv_id, message)
if "error" in result2:
    print("  Got expected error (not found). Recovering...")
    # RECOVERY LOGIC
    result2 = conversation_manager.start_conversation(
        initial_message=message, 
        persona_type=persona_type,
        forced_conversation_id=conv_id
    )

print(f"  Result ID: {result2.get('conversation_id')}")

# Step 4: Verify IDs match
if result2.get("conversation_id") == conv_id:
    print("\nSUCCESS: Recovered conversation with SAME ID!")
else:
    print(f"\nFAILURE: IDs do not match! ({result2.get('conversation_id')} != {conv_id})")

print("="*60)
