# Quilibrium patches

Vendored from `commonware-consensus` 2026.7.0, published from Commonware commit `5950bf7179bb0650a57ed58b9e0478822944b335` (`consensus/`). The published source, normalized manifest and original manifest are retained; the upstream root license files accompany them.

The package is excluded from default workspace membership so its upstream development dependencies do not affect normal Quilibrium builds. Run its unit tests explicitly with its manifest and the upstream `mocks` feature:

```sh
cargo nextest run --manifest-path crates/commonware-consensus/Cargo.toml --features mocks --lib
```

## Lazy vote buffers

`src/simplex/types.rs` defers each `AttributableMap` allocation until its first in-bounds insertion. `src/simplex/actors/batcher/verifier.rs` defers each vote vector until its first add, reserving the original quorum capacity then and when verification first accumulates peer votes. Upstream APIs, signer ordering, duplicate/conflict evidence, certificates and unfinalized history retention are preserved. No wire or pruning changes. Local changes and regression tests are marked `QUILIBRIUM:`.

These changes reduce unused vote-phase capacity when views advance without finalization; they do not remove retained views or resolve the cause of stalled finalization. Related Quilibrium issue: #677.

## Discarded peer message summary

`src/simplex/actors/batcher/discards.rs` replaces the batcher's per-message `block!` warnings for undecodable messages and messages of another epoch with one summary: the first discard is logged at once, later ones at most every ten minutes with counts, distinct peers and the foreign epoch range. Each line names the engine's journal partition (`app-<shard filter>` on an app shard), which `Engine::new` passes to the batcher, so it identifies its session. Messages of another epoch are expected for a while after a committee handoff and log at info; undecodable ones log a warning. The sender is still passed to the `Blocker` as before. Local changes and regression tests are marked `QUILIBRIUM:`.

## Repeated and conflicting vote summary

`src/simplex/actors/batcher/repeats.rs` replaces the per-message `block!` warnings for a member's further vote in a view it already voted in ("invalid signature" for the same vote with other signature bytes, "conflicting nullify", "conflicting notarize", "conflicting finalize", "nullify after finalize" and "finalize after nullify") with a summary per signer: its first repeat is logged at once with the view, signer and participant index, later ones at most every ten minutes with counts by kind, and an end line with totals once the signer has sent none for ten minutes (logged on the next vote the batcher receives). `Round::add_network` returns the kind and signer index instead of logging; the batcher keeps one episode per participant for its epoch and names the engine's journal partition in each line. Votes for two proposals and nullify-plus-finalize are equivocation and log a warning; a re-signed duplicate changes no outcome and logs at info. The sender is still passed to the `Blocker`, and the conflict evidence is still reported, as before. Local changes and regression tests are marked `QUILIBRIUM:`.
