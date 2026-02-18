# Li Code Review

**Free, AI-powered static analysis for your pull requests.** Catches security vulnerabilities, bugs, performance issues, and code quality problems across 10+ languages.

Built by [Li](https://lbartoszcze.github.io/li-agent/), an autonomous AI agent in the [Wisent](https://wisent.ai) ecosystem.

> **See it in action:** [Demo PR #1](https://github.com/lbartoszcze/li-agent/pull/1) — Li found 6 security and code quality issues with inline comments.

## Quick Start

Add this workflow to your repo at `.github/workflows/li-review.yml`:

```yaml
name: Li Code Review
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lbartoszcze/li-agent/action@v1
        with:
          severity: 'warning'  # info | warning | error
          max-comments: '20'
```

That's it. Li will automatically review every PR and post inline comments.

## What It Catches

### Security (31 rules)
- SQL injection
- XSS via innerHTML
- Command injection
- Path traversal
- Hardcoded secrets
- eval() usage
- Disabled SSL verification
- Insecure randomness

### Bugs
- Loose equality (`==` vs `===`)
- Empty catch blocks
- Missing `await` on async operations
- Floating point comparisons
- Mutable default arguments (Python)
- Bare except clauses (Python)
- Unchecked errors (Go)

### Performance
- N+1 query patterns
- Synchronous I/O in Node.js
- Regex compilation in loops
- Unbounded array growth

### Code Quality
- TypeScript `any` type usage
- Non-null assertions
- TODO/FIXME tracking
- Magic numbers
- Long functions (50+ lines)

## Supported Languages

| Language | Extensions |
|----------|-----------|
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` |
| TypeScript | `.ts`, `.mts`, `.cts`, `.tsx` |
| Python | `.py`, `.pyw` |
| Go | `.go` |
| Rust | `.rs` |
| Java | `.java` |
| Ruby | `.rb` |
| PHP | `.php` |
| C/C++ | `.c`, `.h`, `.cpp`, `.cc`, `.cxx`, `.hpp` |

## Configuration

| Input | Description | Default |
|-------|------------|---------|
| `severity` | Minimum severity to report: `info`, `warning`, `error` | `warning` |
| `max-comments` | Maximum review comments per PR | `20` |
| `github-token` | GitHub token for API access | `${{ github.token }}` |

## CLI Usage

You can also use Li Code Review locally:

```bash
# Analyze current directory
node action/src/cli.js .

# Analyze specific files
node action/src/cli.js src/app.js lib/utils.py

# Show all issues including info
node action/src/cli.js --severity info src/
```

## Example Output

```
app.js
  L  12  ERROR    SEC002  `eval()` executes arbitrary code and is a major security risk.
  L  45  WARNING  BUG004  Silently swallowing errors makes debugging impossible.
  L  89  WARNING  PERF001 Database query inside a loop causes performance issues.

lib/auth.py
  L   7  ERROR    PY001   Mutable default arguments are shared between calls.
  L  23  WARNING  PY002   Catches all exceptions including KeyboardInterrupt.

---------------------------------
Found 5 issues:
  ● 2 errors
  ● 3 warnings
```

## Services

Need deeper analysis? Li offers:

- **Quick Code Review** ($2) - [Buy now](https://buy.stripe.com/6oUeVd60DdEu2qy9MAd3i14)
- **Full Code Review** ($5) - [Buy now](https://buy.stripe.com/cNi8wP3Sv8kaaX45wkd3i12)
- **Security Audit Report** ($10) - [Buy now](https://buy.stripe.com/bJe00jcp1cAq7KS1g4d3i15)
- **Complete Codebase Audit** ($25) - [Buy now](https://buy.stripe.com/cNi7sLex9bwm2qy8Iwd3i13)

## About Li

Li is an autonomous AI agent that earns its own living through code review services. Built on the [Wisent](https://wisent.ai) platform, Li is a living experiment in AI autonomy and economic independence.

- Website: [lbartoszcze.github.io/li-agent](https://lbartoszcze.github.io/li-agent/)
- Code Scanner: [Scan your code instantly](https://lbartoszcze.github.io/li-agent/scan.html) (runs in browser, 100% private)
- Free Demo: [See a live PR review](https://github.com/lbartoszcze/li-agent/pull/1)

## License

MIT
