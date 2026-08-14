# Kali + MCP VAPT MVP

This branch adds a URL-first authorized VAPT pipeline to Nayak The Hacker.

## Pipeline

`URL -> httpx -> WhatWeb -> Nmap -> Subfinder -> Amass -> (approved active checks: ffuf/Gobuster/Nuclei/Nikto) -> normalization/deduplication -> OpenAI analysis -> dashboard/JSON`

The application uses fixed subprocess argument lists (`shell=False`) and rejects targets without an explicit authorization flag. Active checks are disabled unless both `authorized=true` and `active_approved=true` are supplied.

## Kali setup

Install the required Kali tools and make sure they are on PATH:

- httpx
- WhatWeb
- Nmap
- Subfinder
- Amass
- ffuf
- Gobuster
- Nuclei
- Nikto

The default wordlist is `/usr/share/wordlists/dirb/common.txt`. Override it with `VAPT_WORDLIST` if your Kali installation uses another path.

## Python setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional AI analysis:

```bash
export OPENAI_API_KEY='YOUR_KEY'
export OPENAI_MODEL='gpt-5'
```

The app uses the OpenAI Responses API for the analysis layer when the key is configured. Without a key, it falls back to local severity prioritization.

## Start backend

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

## Start Kali MCP server

The repository includes `mcp/kali_vapt_server.py` using the official MCP Python SDK. For a local MCP host, run:

```bash
python mcp/kali_vapt_server.py
```

The MCP server exposes `scan_authorized_url(target, authorized, active_approved)`. It shares the same safe orchestrator used by the FastAPI backend, so the UI and MCP path have the same scope controls.

For a Streamable HTTP deployment, expose the MCP server with the SDK's Streamable HTTP transport rather than opening the scanner directly to the public internet. Keep the MCP endpoint on localhost unless a deliberate authenticated deployment is configured.

## API example

Safe/passive pipeline:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://authorized-target.example","target_type":"web","authorized":true,"active_approved":false}'
```

Active checks require an explicit second approval:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://authorized-target.example","target_type":"web","authorized":true,"active_approved":true}'
```

## Scope of the URL-first MVP

A URL can drive web/API reconnaissance and assessment. Mobile VAPT needs an APK/IPA and mobile-specific evidence; cloud VAPT needs cloud configuration/account context; social-engineering VAPT needs an explicitly scoped campaign and human participants. The application does not pretend that a URL alone can assess those domains.

Burp Suite, OWASP ZAP, sqlmap, and Metasploit remain controlled/manual validation integrations and are intentionally not auto-executed by this MVP.
