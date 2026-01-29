// build.rs
//! Build script for compiling protobuf definitions
//! 
//! Protobuf compilation is optional - if protoc is not installed,
//! the daemon module will use fallback types instead of generated code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if proto file exists
    let proto_path = "proto/scanner.proto";
    
    if std::path::Path::new(proto_path).exists() {
        println!("cargo:rerun-if-changed={}", proto_path);
        println!("cargo:rerun-if-changed=proto/");
        
        // Try to compile proto, but don't fail if protoc is not installed
        match compile_proto(proto_path) {
            Ok(_) => println!("cargo:warning=Successfully compiled protobuf definitions"),
            Err(e) => {
                println!("cargo:warning=Protobuf compilation skipped: {}", e);
                println!("cargo:warning=gRPC features will use fallback types. Install protoc for full gRPC support.");
            }
        }
    } else {
        println!("cargo:warning=Proto file not found at {}, skipping gRPC generation", proto_path);
    }
    
    Ok(())
}

fn compile_proto(proto_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Check if protoc is available
    if std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err("protoc not found in PATH".into());
    }
    
    // Create output directory
    let out_dir = "src/daemon/";
    std::fs::create_dir_all(out_dir)?;
    
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(out_dir)
        .compile(&[proto_path], &["proto/"])?;
    
    Ok(())
}
