use regex::Regex;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let circuits_dir = "src/circuits";

    // Create circuits/src directory
    fs::create_dir_all(&circuits_dir)?;

    // Read the original main.nr file
    let original_content = fs::read_to_string("src/main.nr")?;

    // Create regex patterns for each struct (currency stays fixed at 16)
    let amount_regex = Regex::new(
        r"pub struct TranscriptOpeningAmount \{\s*direction: u8,\s*data: \[u8; (\d+)\],\s*blinder: \[u8; 16\],\s*position: u32,\s*\}",
    )?;
    let username_regex = Regex::new(
        r"pub struct TranscriptOpeningUserName \{\s*direction: u8,\s*data: \[u8; (\d+)\],\s*blinder: \[u8; 16\],\s*position: u32,\s*\}",
    )?;

    // Generate circuits for each combination (currency fixed at 16)
    for amount_size in 10..=30 {
        for username_size in 10..=30 {
            let circuit_filename = format!("main_a{}_u{}.nr", amount_size, username_size);

            // Generate modified main.nr content
            let mut modified_content = original_content.clone();

            // Replace Amount struct
            modified_content = amount_regex.replace(&modified_content, 
                format!("pub struct TranscriptOpeningAmount {{\n    direction: u8,\n    data: [u8; {}],\n    blinder: [u8; 16],\n    position: u32,\n}}", amount_size)
            ).to_string();

            // Replace UserName struct
            modified_content = username_regex.replace(&modified_content,
                format!("pub struct TranscriptOpeningUserName {{\n    direction: u8,\n    data: [u8; {}],\n    blinder: [u8; 16],\n    position: u32,\n}}", username_size)
            ).to_string();

            // Write main.nr file
            fs::write(
                format!("{}/{}", circuits_dir, circuit_filename),
                modified_content,
            )?;

            println!("Generated circuit: {}", circuit_filename);
        }
    }

    println!("Generated {} circuit files total in src/circuits/", 21 * 21);
    Ok(())
}
