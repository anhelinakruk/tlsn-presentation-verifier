#!/usr/bin/env python3
import re
import os

def main():
    circuits_dir = "src/circuits"
    
    # Create circuits directory
    os.makedirs(circuits_dir, exist_ok=True)
    
    # Read the original main.nr file
    with open("src/main.nr", "r") as f:
        original_content = f.read()
    
    # Create regex patterns for each struct
    amount_pattern = r"pub struct TranscriptOpeningAmount \{\s*direction: u8,\s*data: \[u8; (\d+)\],\s*blinder: \[u8; 16\],\s*position: u32,\s*\}"
    username_pattern = r"pub struct TranscriptOpeningUserName \{\s*direction: u8,\s*data: \[u8; (\d+)\],\s*blinder: \[u8; 16\],\s*position: u32,\s*\}"
    
    count = 0
    # Generate circuits for each combination (currency fixed at 16)
    for amount_size in range(10, 31):
        for username_size in range(10, 31):
            circuit_filename = f"main_a{amount_size}_u{username_size}.nr"
            
            # Generate modified main.nr content
            modified_content = original_content
            
            # Replace Amount struct
            modified_content = re.sub(
                amount_pattern,
                f"pub struct TranscriptOpeningAmount {{\n    direction: u8,\n    data: [u8; {amount_size}],\n    blinder: [u8; 16],\n    position: u32,\n}}",
                modified_content
            )
            
            # Replace UserName struct  
            modified_content = re.sub(
                username_pattern,
                f"pub struct TranscriptOpeningUserName {{\n    direction: u8,\n    data: [u8; {username_size}],\n    blinder: [u8; 16],\n    position: u32,\n}}",
                modified_content
            )
            
            # Write main.nr file
            with open(f"{circuits_dir}/{circuit_filename}", "w") as f:
                f.write(modified_content)
            
            count += 1
            if count % 50 == 0:
                print(f"Generated {count} circuits...")
    
    print(f"Generated {count} circuit files total in src/circuits/")

if __name__ == "__main__":
    main()
