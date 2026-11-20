# Security policy

## What this is

boundarycheck is a security *testing* tool. It is read-only and, in v0.1, loopback-only. Use it only
against systems you own or are explicitly authorized to assess.

## Reporting a vulnerability in boundarycheck

Please use **GitHub private vulnerability reporting**: the repository's **Security** tab, then
**Report a vulnerability**. Do not open a public issue containing exploit detail.

In scope (please report):

* a way to make the tool send a request that is not a `GET`/`HEAD`, or to a host that is not loopback,
  or to follow a redirect, or to honour proxy environment variables;
* a config file that executes code, exhausts memory or time, reads or writes outside what it should,
  or smuggles a path, host or header into a request;
* a credential, token or private value reaching a report, an evidence file, output, a log or a crash
  message, or a file created with permissions wider than `0600` (directories `0700`);
* a response from a target that corrupts or injects into a report (Markdown or JSON), or crashes the run
  in a way that exits `0` or `1`;
* a way to make a failed, partial or empty run exit `0`.

Out of scope: findings about someone else's API that boundarycheck helps you discover (report those to
that API's owner); the limits listed in [LIMITATIONS.md](LIMITATIONS.md) (they are documented, not
hidden); the deliberately vulnerable lab variant (report issues with *that* in its own repository).

Do not include real credentials, personal data or third-party system details in any report.
You can expect an acknowledgement within a few days. This is a volunteer project and there is no bounty.

## Supported versions

Pre-release. Only the latest commit on the default branch is supported.

## What the tool does and does not protect

It enforces its rules in its own process: loopback-only sockets, read-only methods, no redirects, no
proxy variables, capped and decompression-bounded responses, redaction, a credential-leak guard, private
file permissions. It **cannot** see where a loopback listener forwards (an SSH tunnel or a local proxy
on `127.0.0.1` can reach a remote host), cannot guarantee egress filtering, and cannot grant itself
permission to test anything. A container or a network ACL outside the process is the supported way to
contain it. Details: [LIMITATIONS.md](LIMITATIONS.md).
