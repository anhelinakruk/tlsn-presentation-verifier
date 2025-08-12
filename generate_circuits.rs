use std::fs;
use std::path::Path;
use regex::Regex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let circuits_dir = "src/circuits";
    
    // Create circuits/src directory
    fs::create_dir_all(&circuits_dir)?;
    
    // Read the original main.nr file
    let original_content = fs::read_to_string("src/main.nr")?;
    
    // Create regex patterns for each struct
    let amount_regex = Regex::new(r"pub struct TranscriptOpeningAmount \{\s*direction: u64,\s*data: \[u8; (\d+)\],\s*blinders: \[u8; 16\],\s*position: u32,\s*\}")?;
    let username_regex = Regex::new(r"pub struct TranscriptOpeningUserName \{\s*direction: u64,\s*data: \[u8; (\d+)\],\s*blinders: \[u8; 16\],\s*position: u32,\s*\}")?;
    let currency_regex = Regex::new(r"pub struct TranscriptOpeningCurrency \{\s*direction: u64,\s*data: \[u8; (\d+)\],\s*blinders: \[u8; 16\],\s*position: u32,\s*\}")?;
    
    // Generate circuits for each combination
    for amount_size in 10..=30 {
        for username_size in 10..=30 {
            for currency_size in 10..=30 {
                let circuit_filename = format!("main_a{}_u{}_c{}.nr", amount_size, username_size, currency_size);
                
                // Generate modified main.nr content
                let mut modified_content = original_content.clone();
                
                // Replace Amount struct
                modified_content = amount_regex.replace(&modified_content, 
                    format!("pub struct TranscriptOpeningAmount {{\n    direction: u64,\n    data: [u8; {}],\n    blinders: [u8; 16],\n    position: u32,\n}}", amount_size)
                ).to_string();
                
                // Replace UserName struct
                modified_content = username_regex.replace(&modified_content,
                    format!("pub struct TranscriptOpeningUserName {{\n    direction: u64,\n    data: [u8; {}],\n    blinders: [u8; 16],\n    position: u32,\n}}", username_size)
                ).to_string();
                
                // Replace Currency struct
                modified_content = currency_regex.replace(&modified_content,
                    format!("pub struct TranscriptOpeningCurrency {{\n    direction: u64,\n    data: [u8; {}],\n    blinders: [u8; 16],\n    position: u32,\n}}", currency_size)
                ).to_string();
                
                // Write main.nr file
                fs::write(format!("{}/{}", circuits_dir, circuit_filename), modified_content)?;
                
                println!("Generated circuit: {}", circuit_filename);
            }
        }
    }
    
    println!("Generated {} circuit files total in circuits/src/", 6 * 6 * 6);
    Ok(())
}
