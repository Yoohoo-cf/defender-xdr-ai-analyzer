# AI-Powered Defender XDR Incident Analyzer

> Work in Progress

A security automation project that retrieves incidents from
Microsoft Defender XDR and sends security incident data to a
locally hosted LLM through Ollama for AI-assisted analysis.

## Project Status

🚧 Currently under active development.

### Completed

- Azure/Linux AI lab deployment
- Microsoft Defender XDR API authentication
- Defender XDR incident retrieval
- Local Ollama deployment
- Incident forwarding to Ollama
- Basic LLM-based incident analysis

### In Progress

- Structured incident analysis
- Severity and risk classification
- Prompt engineering for security incidents
- Security analyst recommendations
- Output formatting

### Planned

- Microsoft Sentinel integration
- Automated triage workflow
- MITRE ATT&CK mapping
- IOC extraction
- False-positive assessment
- Incident prioritization
- Security dashboard / UI
- Automated analyst reporting

## Architecture

Microsoft Defender XDR
        |
        v
Defender XDR API
        |
        v
Python Incident Collector
        |
        v
Incident Analyzer
        |
        v
Ollama
        |
        v
Local LLM
        |
        v
AI Security Analysis

## Technologies

- Microsoft Defender XDR
- Microsoft Entra ID
- Azure
- Python
- REST APIs
- Ollama
- Local LLMs
- Linux

## Security

Credentials are not stored in this repository.

Environment variables should be used for:

- TENANT_ID
- CLIENT_ID
- CLIENT_SECRET

See `.env.example`.

## Disclaimer

This project is currently a personal AI security lab and is under
active development.
