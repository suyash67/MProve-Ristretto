# Total estimated time (mins) ~= 1.41
# Note: timings estimated based on Intel® Core™ i7-5500U CPU @ 2.40GHz (on a single core)

cargo build --release
cargo run --release --bin mprove_bin 10000 50 -n 1
cargo run --release --bin mprove_bin 10000 100 -n 1
cargo run --release --bin mprove_bin 10000 200 -n 1
cargo run --release --bin mprove_bin 10000 500 -n 1
cargo run --release --bin mprove_bin 10000 1000 -n 1
cargo run --release --bin mprove_bin 10000 2000 -n 1
cargo run --release --bin mprove_bin 10000 5000 -n 1