# Quilibrium patches

Vendored from `commonware-consensus` 2026.7.0, published from Commonware commit `5950bf7179bb0650a57ed58b9e0478822944b335` (`consensus/`). The published source, normalized manifest and original manifest are retained; the upstream root license files accompany them.

The package is excluded from default workspace membership so its upstream development dependencies do not affect normal Quilibrium builds. Run its unit tests explicitly with its manifest and the upstream `mocks` feature:

```sh
cargo nextest run --manifest-path crates/commonware-consensus/Cargo.toml --features mocks --lib
```

## Lazy vote buffers

`src/simplex/types.rs` defers each `AttributableMap` allocation until its first in-bounds insertion. `src/simplex/actors/batcher/verifier.rs` defers each vote vector until its first add, reserving the original quorum capacity then and when verification first accumulates peer votes. Upstream APIs, signer ordering, duplicate/conflict evidence, certificates and unfinalized history retention are preserved. No wire or pruning changes. Local changes and regression tests are marked `QUILIBRIUM:`.

These changes reduce unused vote-phase capacity when views advance without finalization; they do not remove retained views or resolve the cause of stalled finalization. Related Quilibrium issue: #677.

## Leader fallback past unextendable nullified parents

`src/simplex/actors/voter/state.rs` lets a leader skip a certified view that is also nullified when the application, through the optional `ParentFallback` hook (`src/simplex/config.rs`, installed with `Engine::with_parent_fallback`), says it cannot build on that view's payload; the leader then walks back to the newest certified view it can extend, stopping as before at a certified view that is not nullified and never passing the last finalized view. Without a hook the walk is upstream's. A nullified view can never gather a finalization quorum (an honest voter never casts both votes for a view), and a finalized view can never be nullified, so the walk stops at the last finalized view (or returns `Err` if its round is gone) and skipping loses nothing finalized. Voters, unchanged, accept the older parent because every view between it and the proposal is nullified. The hook is told once per leader turn which views it skipped. With its notarize vote for such a proposal, the leader broadcasts, once, the nullification certificates of the views from just above the parent through the newest skipped view (`State::take_fallback_nullifications`): a voter that certified the late notarization of a skipped view, or caught up past views through a certificate, may lack them, and cannot fetch them, as its resolver fetches only above its newest certified view and a peer answers a request at or below its own with that certificate. Views above the newest skipped view are not forwarded: voters passed them by nullification or fetch them. At most 64 are forwarded per turn, the skipped views first, then a window of the others that advances on each capped turn; a voter still missing one waits until the view times out, so the leader loses only that turn, and the voter keeps what it received for the leader's later turns. Each forwarding turn logs at info how many nullifications it sent, how many views between the parent and the newest skipped view are nullified, and whether the cap applied. These are ordinary certificate messages, so unmodified voters handle them. With perfect links every voter already holds them, so only unit tests exercise the forwarding; the simulated runs in `simplex/mod.rs` do not depend on it. Local changes and regression tests are marked `QUILIBRIUM:`.

## Discarded peer message summary

`src/simplex/actors/batcher/discards.rs` replaces the batcher's per-message `block!` warnings for undecodable messages and messages of another epoch with one summary: the first discard is logged at once, later ones at most every ten minutes with counts, distinct peers and the foreign epoch range. Each line names the engine's journal partition (`app-<shard filter>` on an app shard), which `Engine::new` passes to the batcher, so it identifies its session. Messages of another epoch are expected for a while after a committee handoff and log at info; undecodable ones log a warning. The sender is still passed to the `Blocker` as before. Invalid-signature `block!` sites are unchanged. Local changes and regression tests are marked `QUILIBRIUM:`.
