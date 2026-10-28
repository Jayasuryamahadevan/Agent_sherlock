# Agent Sherlock

A local Windows diagnostic agent with a browser UI. The installed package includes the original evidence-driven engine: AI triage, selective Windows evidence collection, grounded hypotheses, a controlled action catalog, three policy pipelines, approval decisions, verification, simulation, and an audit trail. It also includes a simpler read-only host snapshot in the UI. The AI text path uses the signed-in Antigravity CLI (`agy`).

## Install on the computer to diagnose

Install Python 3.11+ and [Antigravity CLI](https://antigravity.google/docs/getting-started/). Launch `agy` once and sign in with Google. Then:

```bash
python -m pip install --upgrade "git+https://github.com/Jayasuryamahadevan/Agent_sherlock.git"
fieldnote inspect
fieldnote serve
```

On Windows, `py -m pip install ...` may be needed. Open `http://127.0.0.1:8000`. The server binds to loopback. Install it on each computer rather than exposing it over a network.

## Two investigation paths in the UI

**Quick investigation** collects a bounded host snapshot and returns an AI explanation. It runs no repairs. The UI shows stages, read-only collector commands, evidence and a metadata-only audit log at `~/.fieldnote/audit.jsonl`.

**Advanced Windows agent** uses selective collectors and the original policy engine. Choose one of three pipelines:

- Diagnosis only (`automatic_execution`): collects and remeasures evidence; recommends actions without changing the system.
- Ask before eligible changes (`whitelist_approval`): requires a catalogued action, matching parameters, and explicit approval.
- Automatic eligible fixes (`auto_resolution`): can execute allowed low/medium-risk actions, then collects fresh evidence to verify the outcome. Real changes require `DIAG_ALLOW_SYSTEM_CHANGES=1`; some also require an administrator terminal.

On Linux, the advanced engine runs a simulated Windows PC. The quick path inspects the Linux host. The advanced engine's collector and real action commands have unit tests with mocked Windows calls but have **not been run on a real Windows machine**. See [pipeline details](docs/PIPELINES.md).

The original engine has 156 passing automated tests in this repository; they cover simulation, policy, grounding, API, and collectors. A live simulated diagnosis with `gemini-3.8-flash-low` completed and returned a grounded DNS finding. Model accuracy across scenarios and real Windows problems has not been measured.

## Screenshots

Interactive `agy` accepts pasted screenshots. The app's browser upload uses the optional Gemini API route because the signed-in `agy --print` path has no verified image attachment interface. To enable browser screenshots, install `python -m pip install "fieldnote-diagnostics[images]"` and set `GEMINI_API_KEY`; images are held in memory during the request and are not written to the app audit log. This image route has not had a live model test here. Text diagnosis works with Google login alone.

## Limits

The quick app's sessions live in memory. Its audit log records stage metadata and avoids storing complaint text, screenshots and raw evidence. The advanced engine stores an on-disk audit log and keeps API sessions in memory. This local server has no multi-user authentication. Keep it on loopback. Driver, application and update-history evidence coverage remains incomplete. No rollback framework is implemented. An action's successful exit is not treated as proof that the problem was fixed.

To uninstall: `python -m pip uninstall fieldnote-diagnostics`.
