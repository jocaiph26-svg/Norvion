#!/usr/bin/env python3
import os
from anthropic import Anthropic

def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        print("Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        return
    
    client = Anthropic(api_key=api_key)
    conversation_history = []
    
    print("Claude Terminal Chat")
    print("Type 'exit' to quit, 'clear' to reset conversation")
    print("-" * 50)
    
    while True:
        try:
            user_input = input("\nYou: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == "exit":
                print("Goodbye!")
                break
            
            if user_input.lower() == "clear":
                conversation_history = []
                print("Conversation cleared.")
                continue
            
            conversation_history.append({
                "role": "user",
                "content": user_input
            })
            
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=8096,
                messages=conversation_history
            )
            
            assistant_message = response.content[0].text
            conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })
            
            print(f"\nClaude: {assistant_message}")
            
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break

if __name__ == "__main__":
    main()
