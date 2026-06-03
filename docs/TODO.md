# proxlet TODO

Last updated: 2026-06-03

## Next Work

- Add graceful shutdown and connection-count/idle-timeout controls for
  long-running service deployments.
- Add IPv4/IPv6 and CIDR allowlist integration coverage.
- Add multi-platform release validation that inspects produced binaries for
  unintended runtime shared-library dependencies.

## Known Scope

- SOCKS `UDP ASSOCIATE` and `BIND` are not currently implemented; TCP
  `CONNECT` is the supported proxy operation.
- SSH upstream authentication currently supports URL password credentials;
  private-key and agent authentication are future additions.
- SSH upstream server host keys are trusted directly by design; this tool does
  not maintain or enforce `known_hosts` state.
