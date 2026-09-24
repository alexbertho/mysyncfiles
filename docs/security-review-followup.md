# Security review follow-up — 2026-09-24

The complete review transcript was read and its seven distinct findings were
checked against the source, not accepted on the review's authority. Each is
actionable. There are **no rejected false positives**. The repeated report at
the end of the transcript is a duplicate, not seven additional findings.

## Dispositions and regression coverage

| Finding | Code verification and correction | Regression coverage |
| --- | --- | --- |
| P1: public release symlink race | The old separate `symlink_metadata`/`open` could use different inodes and followed parent links. Pin the configured release root, open each component with `O_NOFOLLOW`, and obtain metadata and stream from the same opened regular file. | Static parent/leaf links; 200 atomic swaps per case with a private sentinel; replacement of the configured root. |
| P1: buffering before authentication | The old middleware read up to 8 MiB before verifying the signature, freshness, request binding, session or replay. Verify those first, reserve the nonce transactionally, admit at most eight signed requests, and impose a 30-second body deadline. Verify the body hash and recheck session/revocation after reading. | Unfinished bodies with invalid signatures, expired/future proofs, invalid sessions, altered method/query and replay; ninth simultaneous body rejected; admission released after cancellation; revocation during a body read; byte limit and deadline. |
| P2: concurrent update rollback | Comparing only against the running process's version did not account for a newer install during download. Serialize publication with a persistent filesystem lock, probe the actually installed version under that lock, and refuse replacement by an equal/older candidate. | Two valid signed updates with the older finishing last; a stale process starting afterward; independently held lock; existing invalid-signature, corrupt-binary and incompatible-candidate cases. |
| P2: long-path scan denial of service | Descriptor-relative creation accepted names whose absolute paths could not be traversed by WalkDir. Enumerate both mirrors and conflict copies relative to directory descriptors, with bounded open-descriptor usage. Keep polling if native watcher setup fails. | Download a 4,095-byte path with a 4,093-byte parent; scan again; preserve a conflict; count it; delete remotely and synchronize again. |
| P2: directory/file transition denial of service | A regular-file read rejected a directory before descendant tombstones could be reconciled. Order actual deletions before creations, preserve displaced directories in conflicts, and discard stale observations after replacement. Never recursively delete displaced user data. | Two clients convert directory to file, with and without local edits/untracked files; unrelated files continue; reverse conversion also works; file created in the directory during download survives. |
| P2: unbounded API JSON | Reqwest `.json()` buffered entire responses. All API response decoding now uses a shared streaming byte limit and deadline, including sessions, enrollment, upload progress and mutation responses. | Oversized Content-Length and chunked responses that never reach EOF for manifests, trash and control responses; stalled JSON deadline. |
| P2: unbounded staging writes | The old download checked size only after EOF. Require a nonnegative size, reject mismatched Content-Length, check accumulated size before every write, retain final size/hash checks, and bound read inactivity/total transfer time. | Overlong unfinished chunked body; inconsistent Content-Length; negative/missing size; original local data and state left intact, staging cleaned. |

The release disclosure requires a writer of the public release directory who
does not already have read access to the server's private storage. That narrower
prerequisite does not make it a false positive; a read-only bind mount does not
stop a host-side writer. The fixes do not claim to defend against root or a
compromised process running as the same user.

## Operational limits and remaining concerns

- List responses are capped at 32 MiB, other API JSON at 64 KiB. Oversized lists
  fail closed, never truncate. Large repositories need pagination before they
  outgrow this limit. The server still materializes its manifest in memory.
- Limits bound the reviewed body-buffer attack, not all denial of service.
  Configure proxy connection/rate limits and deployment resource limits.
  An authenticated malicious device can still consume storage or keep requesting
  work; per-device/global quotas and authorization scopes remain future work.
- Download checks enforce the advertised length, not a disk quota. A server
  advertising genuinely huge files can still exhaust available local storage.
- Release signatures and installed-version checks do not prove that the mirror
  is serving the newest release. A compromised mirror can withhold updates;
  offline signing-key protection and a trusted bootstrap remain essential.
- Data is not end-to-end encrypted. The server and terminating proxy can read
  it. Existing backup/history limitations and TPM trust limitations remain as
  documented in the README and device-authentication guide.
- These are repository changes, not a production deployment or publication of
  a new signed client. Physical TPM interoperability still needs validation;
  automated tests use a simulator and an ephemeral test CA.

## Validation

Completed locally for these changes:

- `cargo fmt --all -- --check`: passed.
- `cargo test --locked --offline` in the TPM development container: **37 tests
  passed** (2 unit, 5 release, 19 security regression, 6 synchronization and
  5 TPM tests), none failed or ignored. Eleven tests were added.
- The same five TPM tests on Debian 13 and Arch Linux runtime containers:
  passed on both. TPM error messages in negative tests are expected rejections
  of a wrong key/copied private blob, not test failures.
- `cargo audit --file Cargo.lock`: no known dependency vulnerabilities reported.

Run `cargo fmt --all -- --check` and `cargo test --locked`. The TPM development
container described in `device-auth.md` supplies native dependencies without
installing build tools on the host. Its test `/tmp` must allow execution because
release tests probe signed candidate executables. TPM-only runtime tests may
use a `noexec` temporary directory.
