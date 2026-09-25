# MySyncFiles — repository-wide security and performance review

Date: 2026-09-25. Source: `c9efdcf`, including the current working tree, **not a diff review**. No production code, configuration, deployment or service was changed during the review.

Reviewed the Rust client/server, authentication and TPM implementation, filesystem capabilities, reconciliation, release/update machinery, SQLite queries/transactions, HTTP routes, CLI tools, deployment files, shell scripts, CI and security documentation.

## 1. Security findings, ordered by severity

### High / P1 — TLS-terminating proxies can forge file authority

**Location:** `src/client.rs:302–307`, `448–461`, `1087–1097`.

A compromised TLS-terminating proxy can replace a manifest's revision, size and SHA-256, then return matching malicious file bytes. Only requests have application-level signatures; the manifest and mutation responses have no independently authenticated server provenance. The download hash consequently authenticates bytes against another attacker-controlled value. A loopback response-substitution reproduction installed `attacker bytes` over a previously synchronized file and reported **zero conflicts**, without involving the genuine server or its keys. Forged tombstones can likewise remove local files. This affects an already-installed legitimate client, independently of the documented bootstrap-script trust limitation.

**Fix:** authenticate server metadata and mutation responses with a separately pinned server key, binding responses to the request/freshness context to prevent replay; verify downloads against those authenticated hashes. Alternatively, require authenticated TLS end-to-end to the origin without an untrusted terminating proxy. This is integrity protection, not a claim of end-to-end encryption.

### Medium / P2 — Public enrollment bodies bypass admission control

**Location:** `src/device_auth.rs:457–464`; `src/server.rs:1043–1049`.

Without a separately configured proxy connection cap, an unauthenticated peer can hold many almost-complete enrollment requests. `Json<EnrollStart>` buffers the body **before** the four-permit enrollment semaphore is acquired; `/v1/enroll/finish` likewise has no pre-body admission control. The per-request 256 KiB ceiling does not bound aggregate memory or impose a total body deadline. **64 unfinished requests carrying 16,000,000 bytes remained pending after 32 seconds**, increasing process RSS by **18,168 KiB**; four sampled connections still had no response. No valid invitation was required. Larger floods can exhaust memory/connections; no destructive exhaustion test was performed.

**Fix:** acquire bounded shared admission and apply a total body deadline in middleware before JSON extraction on public enrollment routes; retain byte limits and add proxy connection/rate limits.

### Medium / P2 — A concurrent edit can be deleted with its recovery copy

**Location:** `src/client.rs:979–987`.

An application retaining an open file descriptor can modify the displaced inode while `hash_file` reads its recovery copy. If it modifies an already-read region, the computed digest can still match the earlier observation, so `backup.remove()` unlinks the edited copy. Reproduced three times with a 128 MiB file and a remote tombstone: after the hash reader passed 1,114,112 bytes, an existing writer edited byte zero; the file ended with **zero links and zero reported conflicts**. This is silent loss of a concurrent local edit, not an ordinary intentional overwrite.

**Fix:** do not treat a digest of an unstable inode as sufficient evidence for destructive cleanup. Detect changes across the read and conservatively retain captures when concurrent writing is possible; add a regression involving an already-open writer during recovery hashing. Merely checking the pathname before renaming is insufficient.

**Already documented availability limits:** approved devices can consume unbounded storage; sufficiently large manifests/trash lists exceed the client's 32 MiB ceiling, and tombstones accumulate. These are real capacity/trust limits, not newly discovered authorization bypasses. Quotas, capacity monitoring and pagination remain worthwhile.

## 2. Performance benchmark results

### Method and qualifications

Release-optimized Rust 1.98.1; Debian 13 x86-64; four virtual Haswell-class CPUs; approximately 7.6 GiB RAM; disk-backed ext-family workspace. Fixtures used 4 KiB files in directories of 100 files, plus a 256 MiB large file. Reads were predominantly page-cache hits; caches were not forcibly dropped. Runs were sequential, with three component samples, 20 metadata encode/decode/query iterations, and single full small-file transfer passes. These are descriptive local measurements, not production latency estimates.

The host lacks `libtss2`/`swtpm`, Docker access is denied, and dependency downloads failed DNS resolution. Therefore a separate harness copies the production functions unchanged and adds accessors/fixtures, but **replaces TPM signing/public-area parsing with a software P-256 fixture**. Enrollment is seeded locally. HTTP measurements include the real synchronization/storage code, request-binding verification, replay/session SQLite operations and filesystem durability calls, but exclude real TPM operations, enrollment attestation, TLS and WAN/proxy latency. Server and client share one process. `TCP_NODELAY` and buffered serialization are explicitly labeled counterfactual experiments, not production changes.

| Component | 100 files | 1,000 files | 10,000 files |
|---|---:|---:|---:|
| Enumerate/open files, median | 0.49 ms | 4.56 ms | 50.77 ms |
| Scan + SHA-256, median | 3.71 ms | 28.40 ms | 289.49 ms |
| One complete state checkpoint, median | 3.54 ms | 24.74 ms | 241.29 ms |
| Manifest SQLite query, mean | 0.061 ms | 0.402 ms | 4.242 ms |
| Manifest JSON serialization, mean | 0.020 ms | 0.176 ms | 1.673 ms |
| Manifest JSON deserialization, mean | 0.043 ms | 0.357 ms | 4.037 ms |
| Manifest JSON size | 15,122 B | 151,924 B | 1,528,926 B |
| SQLite metadata fixture insertion, one transaction | 0.82 ms | 4.42 ms | 36.06 ms |

| Complete sync workload | 100 files | 1,000 files | 10,000 files |
|---|---:|---:|---:|
| Initial upload | 0.485 s | 16.559 s | Not run |
| No changes | 0.314 s | **25.445 s** | **Stopped after 30 s; unfinished** |
| Initial download | 4.818 s | 58.967 s | Not run |

The 10,000-file timeout began after fixture preparation. No projected completion time is presented as a measurement.

Additional measurements:

- **State writes:** a 1,000-file no-op pass wrote approximately **144 MB** and made **32,013,015 write-family calls** according to `/proc/self/io`. One 10,000-entry checkpoint made **320,013** such calls. The buffered, equivalent-JSON checkpoint experiment reduced this to **178 calls and 6.93 ms**, versus 241.29 ms for the production checkpoint path; batching/skipping checkpoints would remove much more work still.
- **Idle daemon:** one unchanged file produced **six manifest polls in four seconds**, with no external changes, despite the 15-second polling interval.
- **Small-file network control:** enabling `TCP_NODELAY` only on accepted harness server sockets reduced 100-file download from **4.818 s to 0.386 s**. Reconciliation of 100 genuine conflicts fell from **4.745 s to 0.505 s**; all 100 local versions were retained. Upload/no-op times remained approximately 0.48/0.31 s. This isolates a Nagle/delayed-ACK effect in the streaming response path on the tested persistent connections.
- **Large file:** SHA-256 of 256 MiB took a median **1.225 s**, about **209 MiB/s**. Across two complete workload runs, upload in 32 authenticated 8 MiB chunks took **6.008–6.858 s** (37–43 MiB/s); streamed download took **1.571–2.374 s** (108–163 MiB/s). A no-change pass still took **1.265–1.269 s**, dominated by hashing. RSS after upload/download was about **100 MiB for the combined client/server process**, not one file-sized allocation. The repeat workload's child-resource accounting also reported approximately 100 MiB peak RSS, with 12.51 s user CPU and 3.45 s system CPU over 14.78 s wall time (including three standalone hashes, fixture work and all three synchronization passes). Upload counters show approximately 768 MiB of file reads: scan, upload read and server final verification.
- **SQLite nonce cleanup:** 100 cleanup/insert/commit cycles took **45.7 / 49.1 / 94.4 / 863.1 ms** with **100 / 1,000 / 10,000 / 100,000** live nonce rows. The unindexed expiry predicate scales poorly, though it was not the dominant small-repository cost.
- **Software-only crypto reference:** 10,000 proof verifications took **1.098 s**, and 1,000 software signatures took **0.115 s**. TPM public-area parsing was substituted; **these are not real TPM signing or complete native proof-verification benchmarks**.
- **Metadata-workload RAM:** the component suite through 10,000 files peaked at **27,660 KiB RSS** (approximately 27 MiB), including scan maps, JSON buffers and SQLite fixtures.

Raw measurements, repeat runs, logs and the explicitly non-production harness are retained under `target/review-audit/2026-09-25/` (ignored by Git).

## 3. Main performance bottlenecks

1. **Quadratic state persistence — P1:** `src/client.rs:1072–1080`, `1100–1107`, `1132–1140`, and `149–166`. Every path, including an unchanged one, rewrites and fsyncs the entire state. Unbuffered pretty serialization compounds the problem. At 1,000 files, the no-op pass is about 900 times slower than scanning/hashing alone and exceeds the polling interval.
2. **Self-triggering watcher loop — P1:** `src/client.rs:1209–1212`. `notify`'s Linux backend emits open events from the client's own scans; the callback accepts every successful event. Opening/chmodding `.mysync-staging` also generates events. The daemon repeatedly schedules itself instead of becoming idle, amplifying hashing, state writes, database traffic and TPM use.
3. **Per-file streaming response delay — P2:** `src/server.rs:1083–1085` and the streamed download response. Accepted sockets retain Nagle's algorithm; separately produced headers/body incur delayed-ACK waits on the tested connections. The controlled `TCP_NODELAY` run removed roughly 44 ms per small file. Actual reverse-proxy behavior needs separate measurement.
4. **Content-volume-dependent polling:** every pass rehashes all file contents. The 256 MiB unchanged case is hashing-bound. This is measured overhead, but caching changes must preserve conflict/integrity guarantees rather than blindly trusting a stale mtime.

Blocking filesystem/hash/state operations run directly in async client tasks, and synchronous SQLite operations share one server mutex. Their costs are real, but scheduler responsiveness and multi-device contention were not separately benchmarked. Minor path/string cloning, repeated prefix checks and allocation reductions should not displace the dominant fixes above.

## 4. Optimizations worth implementing, by expected impact

1. **Skip unchanged state writes; batch dirty state updates with crash-safe recovery.** Buffer serialization as well. Preserve atomic publication and durable checkpoints rather than simply deleting fsync calls.
2. **Filter watcher events and client-owned directories.** Ignore read-only access events and staging/conflict housekeeping while retaining real user create/write/rename/delete notifications. Add an idle-daemon regression.
3. **Set `TCP_NODELAY` on accepted API sockets or coalesce headers with initial response data.** Recheck the same workload through the deployed proxy/TLS stack.
4. **Introduce a correctness-aware incremental scan cache** and retain conservative revalidation on reconciliation/conflict paths; move substantial blocking work off async workers. Measure on real mirror sizes before choosing concurrency limits.
5. **Index expiry cleanup and add incremental/paginated metadata APIs** when scaling beyond small personal repositories. Benchmark contention before introducing a database pool; do not sacrifice nonce atomicity or path-namespace transactions.

## 5. Investigated areas already acceptable

- No credible request-authentication/authorization bypass found in the inspected logic: manufacturer EK trust and usage checks, TPM key attributes and activation, explicit administrative approval, request URL/method/body/session binding, transactional nonce reservation and revocation checks are present. Physical/native TPM validation remains outstanding here.
- Filesystem paths reject traversal/reserved components; descriptor-relative `O_NOFOLLOW` traversal and no-replace moves avoid the reviewed symlink escapes. Release-serving parent/leaf/root swap regressions passed in the isolated harness. No new path traversal or symlink escape was demonstrated.
- SQL values are parameterized; revision/namespace checks and mutations share transactions; restore refuses live-file collisions. No SQL injection was identified.
- Signed request admission/body limits, client JSON limits/deadlines, streamed download size/hash validation and 8 MiB upload chunks are meaningful protections. The public enrollment exception is identified above.
- Release signatures, artifact bounds/hash/target checks, publication locks on the updater, installed-version rechecks and fail-closed redirects resisted the executed release tests. No new updater rollback or signature bypass was found. Withholding updates and first-bootstrap trust remain documented limitations.
- The signed installer stages privately, verifies before execution, preserves existing binaries and defers service activation. No additional shell injection or secret disclosure was identified. The source-install helper intentionally accepts a locally trusted binary.
- Deployment separates private data/public releases, drops capabilities, uses a read-only container root and loopback host binding. The HTTP Nginx example is explicitly documented as requiring an upstream TLS terminator, not as a complete HTTPS deployment. No production environment/secrets were printed or tested.
- Manifest serialization and ordinary metadata queries were small compared with the measured persistence/network costs. There is no measurement-based reason to prioritize a faster JSON library or cosmetic clone removal.

## 6. Validation and limits

- **Passed:** repository `cargo fmt --all -- --check`; `sh -n deploy/install.sh`; `bash -n deploy/install-client.sh deploy/install-tpm-deps.sh`.
- **Blocked:** repository `cargo test --locked` fails during dependency compilation because `tss2-sys` is unavailable. Docker fallback was inaccessible; no claim of a passing native/full suite is made.
- **Isolated harness:** the unchanged two body-limit/deadline unit tests, eight installer tests and six release tests passed with `umask 022` (**16 tests**, including the final serialized run). Initially, two installer fixtures failed under the host's `umask 0002`, which creates group-writable pre-existing installation directories. One parallel repeat also encountered `Text file busy` while executing a test script; the subsequent serialized run passed. These harness results do not validate native TPM behavior or replace the complete project suite.
- **Dependency audit:** `cargo audit --file Cargo.lock --no-fetch --no-yanked` found no known advisory matches among 276 dependencies, using the cached advisory database dated 2026-09-24. No online refresh or yanked-package check was possible/performed.
- **Unverified/unbenchmarked:** physical TPMs and complete `swtpm` enrollment, Debian/Arch runtime-container compatibility, real TLS/Cloudflare/WAN transfers, cold-cache disk throughput, multi-device saturation, crash/power-loss consistency and long-duration quota/disk-exhaustion behavior. The 10,000-file full transfer runs were not attempted after the no-op workload exceeded the time budget. Source inspection is not evidence that these untested areas are vulnerability-free.

No production fixes, commits, releases, service activations or production-data operations were performed.
