# Security notes

This plugin is designed to reduce accidental context bloat, not to protect secrets.

- The persistence layer is plaintext SQLite under the active Hermes profile home.
- The plugin skips obvious credential-shaped payloads, but that is a defensive filter, not a guarantee.
- Keep the default TTL and record cap enabled unless you have a separate retention policy.
- Run the test suite and a literal secret-pattern scan before distributing modified builds.
- Do not enable full retrieval by default in shared or high-risk profiles.

If you find a security issue in a public fork, report it through that repository's private vulnerability-reporting channel when available.
