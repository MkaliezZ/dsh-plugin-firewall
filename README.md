# dsh-plugin-firewall

Offline-first static admission scanner for DeepSeek Harness community plugins.

`/plugin-firewall <path>` inspects a local plugin package before you trust it. v0.1 looks for package install scripts, git/URL dependencies, native addons, Cordis/profile patches, tool registration, process/network/filesystem/environment access indicators, and emits a deterministic risk receipt with a SHA-256 digest.

## v0.1 goals

- no network calls or vulnerability database;
- deterministic local analysis;
- explicit LOW / MEDIUM / HIGH findings;
- JSON-safe receipt with digest;
- never executes the scanned plugin;
- does not claim malware detection or complete supply-chain safety.

## Development

```bash
npm install
npm test
```

## License

MIT
