# Releasing to PyPI

Publishing uses **trusted publishing** (OpenID Connect). There is **no PyPI token** in this repository,
in a secret, or on any machine: PyPI is told once that this workflow, in this repository, through this
environment, may publish this project, and each release then proves its identity with a short-lived
token that GitHub mints for that one run. A stolen token cannot exist because none does.

Safeguards, all in `.github/workflows/release.yml`:

* A release is a **tag** `vX.Y.Z`, never a branch push, and the tag must equal the `version` in
  `pyproject.toml` or the build stops.
* The **build job** runs the whole test suite, builds the wheel and sdist, **fails if the lab or any
  `tenantlab` file is inside either one**, installs the wheel in a clean Python 3.13 environment, and runs
  `boundarycheck --version`, `init` and `validate` from it.
* The **publish job** needs the `pypi` GitHub environment, which requires **a named reviewer** to approve
  it and accepts only `v*` tags. Nothing reaches PyPI until that person clicks approve.
* `id-token: write` is granted to the publish job only. Every action is pinned to a full commit SHA.
* Each release carries **PEP 740 attestations**: a signed record of which workflow built which files.

## One-time setup (only you can do this: it is your PyPI account)

1. Sign in to <https://pypi.org> with two-factor authentication on.
2. Open **Your account > Publishing > Add a new pending publisher** and fill in exactly:

   | Field | Value |
   |---|---|
   | PyPI project name | `boundarycheck` (checked free on 2026-11-20) |
   | Owner | `MDPorsch` |
   | Repository name | `boundarycheck` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. In GitHub, the `pypi` environment already exists with you as the required reviewer. Check it at
   *Settings > Environments > pypi*.

That is all. No secret is created anywhere.

## Each release

1. Update `version` in `pyproject.toml` and `src/boundarycheck/__init__.py`, and `CHANGELOG.md`.
2. Merge to `main` through CI (green).
3. `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The workflow builds and verifies. GitHub asks the reviewer to **approve the `pypi` deployment**.
5. After approval PyPI shows the release with its attestations. Check from a clean machine:

   ```bash
   pipx install boundarycheck==X.Y.Z
   boundarycheck --version
   ```

## If something is wrong

* A bad release cannot be replaced: **yank** it on PyPI (Manage > Release > Yank) and release the next
  patch version.
* If the build job fails, nothing was published. Fix on `main` and push a new tag (delete the failed
  tag first: `git push --delete origin vX.Y.Z`, only while nothing was published under it).
* If the publish job fails with "invalid-publisher", step 2 above was not done or a field was mistyped.

## What a release does not do

It does not publish the reference lab (that is a separate repository whose wheel excludes the
deliberately vulnerable variant), and it does not touch remote live mode, which stays on a branch until
you have reviewed its design (`docs/remote-live-design.md`).
