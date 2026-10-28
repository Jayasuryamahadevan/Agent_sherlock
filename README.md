# Agent Sherlock / Fieldnote Diagnostics

A lightweight diagnostic app for the computer on which it runs. It collects bounded system and network evidence and uses your signed-in Antigravity CLI (`agy`) to explain likely causes. The browser interface never runs repairs. The terminal has one separately approved Windows DNS cache action.

## Install

Install Python 3.11 or later and [Antigravity CLI](https://antigravity.google/docs/getting-started/). Run `agy` once to sign in with Google. Then install from this repository:

```bash
python -m pip install "git+https://github.com/Jayasuryamahadevan/Agent_sherlock.git"
fieldnote inspect
fieldnote serve
```

Open `http://127.0.0.1:8000`. On Windows, use `py -m pip install ...` if `python` is unavailable. The `fieldnote` command may require opening a new terminal after installation. No Docker setup is needed for native host inspection.

You can also run `fieldnote analyze "Wi-Fi connects but websites do not load" --dns-host example.com` in a terminal. That command may propose clearing the Windows DNS cache if the named host does not resolve; it requires typing `YES` before any change. Other issues are analysis only.

The app sends your complaint and collected metrics to the model tied to your Antigravity account. It shows uncertainty and should not be treated as proof of a root cause. Antigravity access and usage depend on your Google account. The app binds the web server to `127.0.0.1` and does not provide remote-user authentication. Install it on each friend's own device.

For a clean uninstall: `python -m pip uninstall fieldnote-diagnostics`.

## Activity, screenshots, and logs

The browser UI accepts a complaint and optional DNS hostname, shows the current investigation stages, collected evidence, and the read-only collector commands. It does not execute repair commands. Session event metadata is appended to `~/.fieldnote/audit.jsonl` on the host. The audit log excludes complaint text, screenshots, and raw evidence; the current session's full evidence is kept in memory until the app restarts. The UI is local-only and should not be exposed publicly.

Screenshot analysis is optional and requires a separate Gemini API key because the signed-in `agy --print` interface has no documented file attachment mechanism. Install the extra with `python -m pip install "fieldnote-diagnostics[images]"`, set `GEMINI_API_KEY`, and upload a PNG or JPEG under 6 MB. The image is held in memory for the model request, not saved in the app's audit log. Without the key, text diagnosis through your Antigravity login still works; the UI explains why a screenshot cannot be submitted.

The app supports Linux and Windows host inspection paths, but only the Linux path has been run here. Windows PowerShell collection and the optional terminal DNS cache action still require verification on a Windows machine. The AI may be wrong, and Wi-Fi or Ethernet problems are analyzed rather than automatically repaired.
