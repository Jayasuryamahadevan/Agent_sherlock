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
