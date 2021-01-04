set -ex

rustup update nightly
cargo install --force cargo-fuzz

if ! command -v grcov &>/dev/null; then
    cargo install grcov
fi

cargo clean
CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests" RUSTDOCFLAGS="$RUSTFLAGS" cargo +nightly test
for target in $(ls fuzz/fuzz_targets);do
    cargo +nightly fuzz run "${target%.*}" -- -max_len=66000 -runs=10000
done
grcov ./target/debug/ --source-dir . -t html --branch --ignore-not-existing --llvm -o ./target/grcov/
firefox target/grcov/index.html

set +ex
