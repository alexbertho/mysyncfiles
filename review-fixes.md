# Review fixes and verification — 2026-09-25

All six findings in `review-results.md` were checked against the current source before edits and confirmed. The review report was preserved.

## Findings and regression coverage

| Finding | Verification and correction | Regression coverage |
| --- | --- | --- |
| Proxy can forge file authority | The client accepted unsigned manifests and mutation acknowledgements. The server now signs authenticated API responses with its own persistent Ed25519 key. The client pins an administrator-provided public key, verifies the response status and JSON body, and binds each response to the complete fresh TPM request proof. Streamed files remain checked against authenticated manifest hashes and sizes. | A terminating proxy attempts forged file metadata, tombstones, upload acknowledgements, status changes, missing signatures and replay. Files and state remain intact on rejection; legitimate retries converge. Wrong and missing pins are rejected; the server key survives reopening its database. |
| Enrollment bodies bypass admission | `Json` previously ran before the handler's semaphore. Shared admission now runs before extraction on `start`, `finish` and `ready`, with four permits, a total 30-second body deadline, and the existing byte limits. The permit remains held through the handler. | Incomplete requests fill all four permits. Further requests receive 429 before sending a body; admitted requests time out with 408. Invalid JSON and oversized bodies release permits. |
| Concurrent recovery edit can be deleted | A matching digest alone previously authorized removal. Recovery hashing now compares descriptor metadata before and after reading, including nanosecond mtime/ctime, size, device/inode and link count; an unstable capture is retained. | A deterministic test writes into an already-read region through an existing descriptor. The original 128 MiB complete reconciliation reproduction now retains one inode link and reports one conflict. |
| Quadratic state persistence | Every path previously rewrote and fsynced all entries, including unchanged ones. Unchanged observations now skip persistence. Changed passes publish one buffered atomic snapshot. Small durable mutation records are journaled between snapshots and replayed after interruption; the snapshot and parent directory are synced before retiring the journal. | Cancellation before snapshot publication, a torn journal tail, replay after publication, and unchanged inode/mtime across a no-op pass. Existing conflict, deletion, directory transition and retry tests also pass. |
| Self-triggering watcher loop | Every successful notify event previously scheduled a pass, including scanner opens and staging chmods. Read-only access and housekeeping under reserved directories are now filtered. User mutations, writable closes, rescan notifications and renames back into the mirror remain actionable. | Event classification tests and a real idle daemon: exactly one manifest poll in four seconds, with unchanged state. The existing create/write/remote polling daemon test passes. |
| Nagle delay on streamed files | The accepted sockets used their default Nagle setting. The production listener now sets TCP_NODELAY on every accepted connection. | Accepted socket option assertion, direct HTTP control measurements, and isolated Nginx measurements using the deployment template and persistent upstream connections. |

The new origin protocol does not change device authentication: the non-exportable TPM key, trusted EK chain, activation proof and administrative approval remain required. HTTPS restrictions, disabled redirects, descriptor-relative mirror operations, release verification and transfer limits remain exercised by the native tests. Response signatures provide integrity, not end-to-end encryption or a backup history.

## Client migration

Deploy the updated server before updated clients. Obtain the installation's public key from the administrator's local `mysync-server server-key --data-dir DIRECTORY` command and convey it through an independently trusted channel. Existing clients then run:

```sh
mysync trust-server --public-key KEY_HEX
mysync sync
```

For new clients, `setup` and `enroll` accept `--server-public-key`; interactive setup prompts if omitted. `make pair` displays the key before requesting the client code. The installer forwards `MYSYNC_SERVER_PUBLIC_KEY` when supplied and gives setup a terminal even when invoked through a pipe.

Missing pins and unsigned old servers fail closed. The private origin key is stored with the private SQLite database, independently of the release signing key. Preserve it in database backups. The full protocol and migration instructions are in [docs/device-auth.md](docs/device-auth.md#authenticite-des-reponses-et-migration).

## Benchmarks

The original review harness was refreshed with the corrected production sources and the same fixture accessors. As in the original measurements, it substitutes a software P-256 signer for TPM operations and seeds enrollment locally. Origin Ed25519 signing/verification and real synchronization, storage, request binding, replay checks and durability are included. Native TPM behavior was validated separately with swtpm.

Measurements use optimized Rust 1.98.1 on the same Debian 13 x86-64 host, warm filesystem caches and disk-backed fixtures. Small files are 4 KiB. Component values are medians of three samples; complete workloads are single local passes, not production latency estimates. No external Cloudflare/TLS path was benchmarked.

| Workload | Original review | Corrected code |
| --- | ---: | ---: |
| No-op, 100 files | 0.314 s | 0.00585 s |
| No-op, 1,000 files | 25.445 s | 0.0364 s |
| No-op, 10,000 files | Unfinished after 30 s | 0.365 s |
| Initial upload, 100 files | 0.485 s | 0.358 s |
| Initial upload, 1,000 files | 16.559 s | 2.994 s |
| Initial download, 100 files | 4.818 s | 0.254 s |
| Initial download, 1,000 files | 58.967 s | 2.311 s |
| Reconcile 100 conflicts | 4.745 s | 0.259 s; all 100 versions retained |
| Full checkpoint, 1,000 entries | 24.74 ms | 1.73 ms |
| Full checkpoint, 10,000 entries | 241.29 ms | 11.11 ms |
| Idle manifest polls in four seconds | 6 | 1 |

For the 1,000-file no-op, combined client/server `/proc/self/io` now records 174,054 bytes in `wchar` and 20 write-family calls, compared with roughly 144 MB and 32 million calls. These counters include sockets and server authentication persistence; the client snapshot is not rewritten. A forced 10,000-entry checkpoint uses 178 write-family calls, versus 320,013 previously.

The 256 MiB workload remains dominated by content hashing: median hash 1.267 s, no-op 1.276 s, authenticated chunk upload 5.998 s and streamed download 2.095 s. Combined client/server RSS is about 100 MiB. No metadata-only scan cache or hash bypass was introduced.

### Socket controls through Nginx

These controls use the corrected code throughout, changing only TCP_NODELAY on accepted API sockets. The Nginx containers use ephemeral loopback ports and the repository's `deploy/nginx-sync.conf`; the persistent variant additionally enables an upstream keepalive pool and clears the upstream Connection header.

| 100-file download | Nagle enabled | TCP_NODELAY enabled |
| --- | ---: | ---: |
| Direct persistent HTTP | 4.563 s | 0.254 s |
| Nginx deployment template | 0.272 s | 0.278 s |
| Nginx with persistent upstream connections | 4.578 s | 0.251 s |

The template closes upstream connections and shows no material Nagle penalty. The persistent configuration reproduces and removes the delay. These results establish the socket fix and its dependence on proxy connection policy; they do not establish latency through an external deployed proxy.

### Security reproductions

The unsigned-response substitution is rejected before changing the mirror. The late-write reproduction preserves the edited recovery file and reports a conflict. With 64 unfinished public enrollment requests, 60 receive HTTP 429 immediately and the four admitted bodies receive HTTP 408 by the 32-second observation. The corrected measurement increased RSS by 1,572 KiB, compared with 18,168 KiB in the original review. This is a bounded local reproduction, not an exhaustion test.

## Validation and artifacts

- `cargo fmt --all -- --check`: passed.
- Full native `cargo test --locked`, in the existing TPM development container: **66 passed**, none failed or ignored. This includes installer, releases, all existing security and sync scenarios, origin attacks, and TPM flows.
- The complete 15-test TPM integration executable also passed in both Debian 13 and Arch runtime images, with swtpm, a read-only container root and dropped capabilities.
- `sh -n deploy/install.sh`, `git diff --check`, and strict MkDocs build: passed.

The host lacks native TPM libraries, so native tests ran in Docker rather than using the software benchmark harness. Physical TPM hardware and the external production proxy were not exercised.

Raw measurements, test logs, proxy configurations, benchmark runner and the exact isolated harness are retained under the Git-ignored `target/review-fixes/2026-09-25/`. No production database, service or published release was changed, and no commit or push was made.
