---
name: workspace-agent-instructions
description: "Global workspace instructions for the agent: prefer shell tooling, forbid Python for utility tasks."
applyTo: "**/*"
---

Context
- This repository contains helper tools and tests that call system utilities (`ssh-keygen`, `ssh-agent`, `ssh-add`, `xxd`, `diff`, etc.).

Core Rules (mandatory)
- **Do not write or run Python scripts** for utility tasks, binary analysis, or blob comparisons. If a Python solution is proposed, decline and provide a shell equivalent.
- **Prefer POSIX shell scripts** (`/bin/sh` or `bash`) or preinstalled system commands for tooling, light parsing, hexdumps, and binary diffs.
- For binary comparison tasks, use `xxd`/`hexdump`, `dd`, `cmp`, `diff`, `cut`, `awk`, `sed`, `od`, or `openssl` as appropriate.
- If an external library is required, ask for explicit approval and propose a shell alternative when possible.
- **Go code rules:** structs must be unexported (private) and the package should expose functionality via exported interfaces and constructor functions (e.g., `NewXxx() Xxx`). Avoid exporting concrete struct types from packages; export interfaces instead. Use small, focused interfaces that capture the required methods.
- **Avoid obsolete Go packages:** do not use deprecated or legacy packages such as `io/ioutil`. Prefer `os.ReadFile`, `os.WriteFile`, and modern APIs from the standard library.

Recommended Practices
- Provide copy-pasteable shell command examples that are easy to run.
- When adding a script, place it in `Tools/` with a `#!/usr/bin/env sh` header and make it executable.
- Document the script logic briefly (1–3 lines) in the header.

Interaction Behavior
- Before adding any non-shell utility file (e.g., Python), request the user's explicit approval.
- When analyzing SSH certificates or producing hexdumps, first produce the required shell command sequence and ask permission to run them.

Automated Refusal Example
- If a proposal contains `python`, respond: "Sorry — do not use Python here. I can convert this logic to shell/native tools; would you like me to do that?"

Exceptions
- Any non-shell language must be explicitly approved by the user before use.

Reference Files
- Tooling scripts should live in `Tools/` and tests that call those scripts should remain in `Tests/`.
