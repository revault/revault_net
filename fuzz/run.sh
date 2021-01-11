cargo install --force cargo-fuzz
for target in $(ls fuzz/fuzz_targets);do
    cargo +nightly fuzz run "${target%.*}" -- -max_len=66000 -runs=20000
done
