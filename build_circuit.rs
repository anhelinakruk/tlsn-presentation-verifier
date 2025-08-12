use std::env;
use std::fs;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <amount_size> <username_size> <currency_size>", args[0]);
        eprintln!("Example: {} 10 12 15", args[0]);
        return Ok(());
    }
    
    let amount_size: u32 = args[1].parse()?;
    let username_size: u32 = args[2].parse()?;
    let currency_size: u32 = args[3].parse()?;
    
    if amount_size < 10 || amount_size > 30 ||
       username_size < 10 || username_size > 30 ||
       currency_size < 10 || currency_size > 30 {
        eprintln!("Error: Sizes must be between 10 and 30");
        return Ok(());
    }
    
    let circuit_file = format!("src/circuits/main_a{}_u{}_c{}.nr", amount_size, username_size, currency_size);
    
    if !std::path::Path::new(&circuit_file).exists() {
        eprintln!("Error: Circuit variant {} not found", circuit_file);
        return Ok(());
    }
    
    // Copy the selected circuit to main.nr
    fs::copy(&circuit_file, "src/main.nr")?;
    println!("Using circuit: Amount={}, UserName={}, Currency={}", amount_size, username_size, currency_size);
    
    // Compile with nargo
    let output = Command::new("nargo")
        .arg("compile")
        .output()?;
    
    if output.status.success() {
        println!("✓ Circuit compiled successfully!");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        eprintln!("✗ Compilation failed:");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(())
}