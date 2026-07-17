# Darqual Simulator

`darqual-sim` is the deterministic adversarial experiment harness for the research track. It is intentionally independent of Tor and production persistence.

## Current foundation

- deterministic `(epoch, sequence)` event ordering;
- research default committee `n=4`, `f=1`, finalization quorum `3`;
- client submission, exclusion, dropped submission, corruption, finalization, handoff, and erasure event vocabulary;
- privacy-safe abort when the modeled Byzantine threshold is exceeded;
- finalization blocked when a client exclusion is detected.

## Scope boundary

The current model does **not** simulate cryptographic shares, network timing, proactive refresh, message demand, cover traffic, or privacy games yet. It establishes the reproducible state-machine substrate those experiments will use.

## Commands

```bash
cargo test -p darqual-sim
cargo clippy -p darqual-sim --all-targets -- -D warnings
```

## Next experiments

1. share-generation tracking across committee refresh;
2. negative control without refresh;
3. post-service corruption without erasure;
4. handoff overlap corruption;
5. participant-set commitment and partitioned views;
6. fixed-rate versus demand-driven traffic traces.
