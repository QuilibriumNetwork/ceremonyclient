# RPM
Based on the paper [RPM: Robust Anonymity at Scale](https://eprint.iacr.org/2022/1037). Built to be used as a primitive – all sharp edges are exposed, using this without properly checking the boundaries of the input will cut!

Includes UniFFI UDL file for FFI integration.

## How to use safely
There are six public functions of interest for builders to use if they want to have a purpose built mixnet:

- rpm_generate_initial_shares
- rpm_combine_shares_and_mask
- rpm_sketch_propose
- rpm_sketch_verify
- rpm_permute
- rpm_finalize

### rpm_generate_initial_shares
Performs the first of four steps of the "offline" phase of RPM Variant 3 (Subvariant 2). Each active dealer in a given offline batch generates initial shares of the permutation matrices and masks. Assumes player identifiers are in monotonically increasing order starting from 1, player count must be greater than or equal to the square of dealers. For malicious security, a ZKPoK should be used for each share set and broadcasted by all dealers prior to the next step.

### rpm_combine_shares_and_mask
Performs the second of four steps of the "offline" phase. Each player should have received their respective shares and organized them according to sequence of players for inputs. For malicious security, the ZKPoK should be verified after invoking this. The splits of the permutation matrices and masks should be passed into the next step.

### rpm_sketch_propose
Performs the third of four steps of the "offline" phase. Each player should take the splits of the permutation matrices and masks and pass them into this function. All players should broadcast the sketch proposals.

### rpm_sketch_verify
Performs the fourth step of the "offline" phase. Each player should take the broadcasted sketch proposals and pass them into the function. If any dealer or player had cheated, it would be revealed by the intersection of failures.

### rpm_permute
Performs the first step of the "online" phase. Before invoking this, each message sender should obtain a vector of the first depth's mask shares, at the same index from each, from as many players as needed to match the dealer count. The sender should combine these shares to produce the mask for their message, and add it to their message (chunked by field element size if need be), and secret share it with the same parameters (t = dealers, n = players). The players will collect their respective shares of inputs into an input vector following the order of the mask shares that were applied. The players will then pass in the input vector shares, matrix shares, mask shares, and combined matrix/mask shares from `rpm_combine_shares_and_mask`, along with the depth and player identifiers in player order. This function should be invoked in as many rounds as there is depth to the mixnet, using the previous invocation's output shares given to each respective player. This must be repeated for each chunked vector of field elements if applicable.

### rpm_finalize
A convenience funciton which recombines the shares of the final invocation of `rpm_permute`'s output into the finalized vector of the mixnet.
