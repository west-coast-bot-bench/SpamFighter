# SpamFighter Public Export

SpamFighter is a Discord moderation bot focused on detecting and removing spam. This public export contains the bot engine and setup scaffolding only.

Private detector expressions, production rules, databases, runtime reports, blocklists, tokens, and deployment-specific configuration are intentionally excluded.

## What Is Included

- `SpamFighter.py`: bot runtime with private static spam patterns replaced by non-matching placeholders
- `requirements.txt`: Python dependencies
- `Dockerfile`: container build
- `config.example.toml`: safe configuration template
- `spam_rules.example.toml`: empty managed-rule template
- `.env.example`: environment variable template
- `compose.example.yaml`: optional Docker Compose template

## What You Must Provide Privately

- Discord bot token
- Server and channel IDs
- Your real managed spam rules in `spam_rules.toml`
- Optional domain blocklists under `domain_blocklists/`
- Optional OpenAI API key for AI-assisted rule review
- Runtime state database and report files

## Discord Setup

Invite the bot with these OAuth2 scopes:

```text
bot applications.commands
```

Recommended permissions for full operation:

```text
View Channels
Send Messages
Send Messages in Threads
Embed Links
Attach Files
Read Message History
Manage Messages
Moderate Members
Kick Members
Ban Members
Manage Channels
```

Enable the **Message Content Intent** in the Discord Developer Portal. Put the bot role above roles it needs to timeout, kick, or ban.

## Local Setup

1. Create and activate a virtual environment.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

3. Copy example files.

```powershell
Copy-Item .env.example .env
Copy-Item config.example.toml config.toml
Copy-Item spam_rules.example.toml spam_rules.toml
```

4. Edit `.env`, `config.toml`, and `spam_rules.toml` with your private values.

5. Start the bot.

```powershell
python SpamFighter.py
```

## Docker Setup

```powershell
Copy-Item compose.example.yaml compose.yaml
Copy-Item .env.example .env
Copy-Item config.example.toml config.toml
Copy-Item spam_rules.example.toml spam_rules.toml
docker compose up --build
```

## Rule Configuration

This public export does not include useful spam signatures. Add your rules privately in `spam_rules.toml`.

The empty template supports:

- exact artifact values
- image SHA-256 hashes
- hook regexes for managed detector families
- custom regex rules

Keep `spam_rules.toml`, `spam_rules_history/`, databases, and runtime reports out of git.

## Disclaimer

This repository is a sanitized public export of SpamFighter. It does not include private production regexes, managed spam rules, domain blocklists, databases, runtime reports, credentials, API keys, or deployment-specific configuration.

The included detector placeholders are intentionally incomplete and are not represented as production-ready spam protection. Anyone deploying this project is responsible for supplying their own rules, reviewing moderation behavior, configuring Discord permissions correctly, protecting secrets, and complying with Discord's Terms of Service and all applicable laws.

SpamFighter can delete messages and take moderation actions such as timeouts, kicks, or bans when configured to do so. Test in dry-run mode first and review logs before enabling enforcement in a real server.

## License

This project is licensed under the GNU General Public License v3.0. See `LICENSE` for details.

This software is provided without warranty; see the GPL-3.0 license text for the full warranty disclaimer and limitation of liability.
