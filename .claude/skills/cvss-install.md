# CVSS Install Skill

Install the CVSS CLI tool and use the Go SDK as a library dependency.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/downloads/

## CLI Installation

### From GitHub Release (Recommended)

Download the pre-built binary for your platform from [GitHub Releases](https://github.com/scagogogo/cvss-skills/releases/latest).

Available platforms (33 binaries):

| OS | Architecture | Download |
|---|---|---|
| Linux | x86_64 (amd64) | `cvss-skills_*_linux_x86_64.tar.gz` |
| Linux | aarch64 (arm64) | `cvss-skills_*_linux_aarch64.tar.gz` |
| Linux | armv5/v6/v7 | `cvss-skills_*_linux_armv*.tar.gz` |
| Linux | i386 | `cvss-skills_*_linux_i386.tar.gz` |
| Linux | ppc64le, s390x, riscv64 | `cvss-skills_*_linux_*.tar.gz` |
| macOS | x86_64 (Intel) | `cvss-skills_*_darwin_x86_64.tar.gz` |
| macOS | aarch64 (Apple Silicon) | `cvss-skills_*_darwin_aarch64.tar.gz` |
| Windows | x86_64 | `cvss-skills_*_windows_x86_64.zip` |
| Windows | aarch64 | `cvss-skills_*_windows_aarch64.zip` |
| Windows | i386 | `cvss-skills_*_windows_i386.zip` |
| FreeBSD | x86_64, aarch64, arm | `cvss-skills_*_freebsd_*.tar.gz` |
| NetBSD | x86_64, aarch64, arm | `cvss-skills_*_netbsd_*.tar.gz` |
| OpenBSD | x86_64, aarch64, arm | `cvss-skills_*_openbsd_*.tar.gz` |

### Quick Install (Linux/macOS)

```bash
# One-line install (detects OS and architecture)
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_$(curl -s https://api.github.com/repos/scagogogo/cvss-skills/releases/latest | grep -oP '"tag_name":\s*"v[^"]*"' | head -1 | sed 's/"tag_name":\s*"v//;s/"//')_$(uname -s | tr A-Z a-z)_$(uname -m | sed 's/x86_64/x86_64/;s/aarch64/aarch64/;s/armv7l/armv7/') .tar.gz | tar xz cvss

# Or manually:
# 1. Download the archive for your platform
# 2. Extract the 'cvss' binary
# 3. Move to /usr/local/bin or anywhere in your PATH
tar xzf cvss-skills_0.1.0_linux_x86_64.tar.gz
mv cvss /usr/local/bin/
```

### Quick Install (Windows)

```powershell
# Download from PowerShell
Invoke-WebRequest -Uri "https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_0.1.0_windows_x86_64.zip" -OutFile "cvss.zip"
Expand-Archive cvss.zip
Move-Item cvss.exe C:\Users\YourUser\bin\
```

### Install with Go

```bash
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
```

This installs the `cvss-cli` binary to `$GOPATH/bin`. You may need to rename it:

```bash
mv $(go env GOPATH)/bin/cvss-cli $(go env GOPATH)/bin/cvss
```

### Verify Installation

```bash
cvss --version
# Output: cvss version v0.1.0 (or dev if built from source)

cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Output: 9.8 (Critical)
```

## Go SDK Usage

### Add as Dependency

```bash
go get github.com/scagogogo/cvss-skills@latest
```

### Import in Go Code

```go
import (
    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)
```

### Quick Start

```go
// Parse and score in one step
cv, score, severity, err := parser.ParseAndScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Score: %.1f (%s)\n", score, severity)

// Build with functional options
cv, err = cvss.NewCvss3xWithOptions(
    cvss.WithVersion31(),
    cvss.WithCriticalBase(),
)

// Calculate all scores
calc := cvss.NewCalculator(cv)
scores, err := calc.GetAllScores()
```

## CLI Commands Overview

| Command | Description |
|---------|-------------|
| `cvss score` | Calculate CVSS scores |
| `cvss parse` | Parse a vector string |
| `cvss validate` | Validate a vector string |
| `cvss build` | Build from metric flags |
| `cvss describe` | Human-readable description |
| `cvss diff` | Compare two vectors |
| `cvss merge` | Merge two vectors |
| `cvss equal` | Check vector equality |
| `cvss distance` | Calculate distance metrics |
| `cvss modify` | Modify metric values |
| `cvss convert` | Convert between v3.0/v3.1 |
| `cvss canonicalize` | Reorder to canonical order |
| `cvss analyze` | Impact/sensitivity analysis |
| `cvss range` | Score range for partial vectors |
| `cvss enumerate` | List metric definitions |
| `cvss severity` | Lookup severity from score |
| `cvss preset` | Generate preset vectors |
| `cvss random` | Generate random vectors |
| `cvss json` | JSON serialization |
| `cvss subs` | Display sub-scores |
| `cvss groups` | Display metric groups |
| `cvss map` | Output key=value pairs |
| `cvss get` | Get single metric value |
| `cvss base-only` | Strip to base metrics |
| `cvss sort` | Sort vectors by score |
| `cvss batch` | Batch operations |
| `cvss csv` | CSV file I/O |
| `cvss completion` | Generate shell completions |

All commands support `--format json` for structured output.