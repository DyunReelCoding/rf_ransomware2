import os
import sys
import json

def main():
    while True:
        # Read input from Chrome extension (no input expected, just a read)
        input_data = sys.stdin.read()
        if not input_data:
            break
        
        # Fetch the current user's username based on the platform
        username = os.getlogin()  # This will work on both Windows and Linux
        
        # Output the username as a JSON string
        output_data = {"username": username}
        sys.stdout.write(json.dumps(output_data) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
