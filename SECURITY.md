# Security policy

## Reporting

Email security reports to the CurbApps maintainers. Do not open a public
issue for a live cryptographic defect.

## Supported versions

Only the latest tagged release on this repository is supported.

## Non-goals

This library cannot make browser-extension auto-unlock as strong as a master
password. Hosts that persist a raw AEK in `browser.storage.local` must say so
in their own threat model.

Do not claim this package has been independently audited until an external
review is published and linked from AUDIT.md.
