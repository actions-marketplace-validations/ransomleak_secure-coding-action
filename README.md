# RansomLeak Secure Coding Lessons

This Action reads the SARIF file from your scanner and, when it reports a type of issue we have a lesson for on a pull request, comments on the pull request with a link to a short free lesson (5-10 minutes). You don't sign up and you don't add a secret.

It works with CodeQL, Semgrep, Trivy, Gitleaks or any scanner that writes SARIF with CWE tags. A finding with only an OWASP tag gets no lesson.

**What's covered:** SQL injection, cross-site scripting (XSS), path traversal, command injection, server-side request forgery (SSRF), hard-coded secrets, XML external entities (XXE), open redirect, cross-site request forgery (CSRF) and vulnerable dependencies. Deserialization and weak cryptography have no lesson yet.

The comment reflects what your scanner reports, not only what the pull request changed. For less noise, run the scanner on changed files or with a baseline. When a SARIF result has a `baselineState`, only `new` and `updated` results count.

## Usage

```yaml
name: Security scan
on: pull_request

permissions:
  contents: read
  pull-requests: write
  id-token: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... run your scanner and write results.sarif ...
      - uses: ransomleak/secure-coding-action@v1
        with:
          sarif: results.sarif
```

`id-token: write` lets the Action prove to RansomLeak which repository and pull request it runs in, using a GitHub OIDC token. `pull-requests: write` lets it post the comment with the built-in `GITHUB_TOKEN`.

| Input          | Required | Default               | Description                          |
| -------------- | -------- | --------------------- | ------------------------------------ |
| `sarif`        | yes      |                       | Path to the SARIF file.              |
| `github-token` | no       | `${{ github.token }}` | Token used to post the comment.      |

Use the default token. A token with a different identity posts the comment as that identity, so each rerun creates a new comment instead of updating the first one.

## What is sent

Only these fields go to `https://app.ransomleak.com/api/github-jit/action`:

- The pull request number.
- For each distinct finding: the scanner name, its CWE ids, and whether the rule is a CVE or GHSA advisory.
- Your repository and owner, which RansomLeak reads from the OIDC token, not from the request body.

No code, file paths, messages or snippets leave the runner. Only rules that produced a result are used, not the whole ruleset. Duplicates are removed and the list is capped at 200 findings.

Each lesson link holds a token with the repository owner name, which is a username for personal repositories, the repository name, the pull request number, the lesson and internal ids. A finished lesson needs them to reach the right pull request. The token is signed, not encrypted, so anyone with the link can decode it and read those values.

When a lesson link is first created for an account without the App, RansomLeak keeps one record holding only the numeric GitHub account id, with no personal name. To remove it, ask through [support](https://ransomleak.com/contact-us/).

## What it does not do

- It never fails your workflow. If RansomLeak is unreachable, the token is read-only, the SARIF file is missing, invalid or larger than 50MB, or the request takes more than 10 seconds, the Action logs a warning and exits successfully.
- Pull requests from forks are not currently supported, because GitHub gives those runs a read-only token and no OIDC token.
- It does not record lesson completion. Without the RansomLeak Secure Coding GitHub App there is nothing to write back with, so the comment is not ticked and no check is set. Installing the App records completions on the pull request.
- If the App is installed for your account, the App posts the comment and the Action adds nothing. A pull request that started with the Action and then gets the App, or the reverse, can show a second comment.

## Concurrent runs

Runs on the same pull request can overlap. After writing, the Action re-reads the comments. If more than one lesson comment by `github-actions[bot]` exists, it keeps the oldest, merges the lessons into it and deletes only its own extras. `pull-requests: write` covers this. A failure here is a warning and the workflow still passes.

Two runs editing one comment at the same moment can still overwrite each other, because GitHub has no conditional update. The next run with findings corrects it.

## Runtime

The Action runs on Node 24 (`node24`) and ships a bundled `dist/index.js`.

## License

MIT
