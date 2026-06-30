fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use vendored protoc so CI builds don't depend on system protobuf
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }
    tonic_build::compile_protos("proto/tunnel/v1/tunnel.proto")?;
    Ok(())
}
