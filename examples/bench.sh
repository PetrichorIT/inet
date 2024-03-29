cd axum
cargo b -r
hyperfine -w 3 'RUST_LOG=off cargo r -r >> /dev/null' >> bench.log

cd ..
cd dns-tcp-network
cargo b -r
hyperfine -w 3 'RUST_LOG=off cargo r -r >> /dev/null ' >> bench.log