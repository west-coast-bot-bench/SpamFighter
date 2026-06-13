# SpamFighter Privacy Policy

Effective date: June 13, 2026

This Privacy Policy explains how the public SpamFighter Discord bot software published at `west-coast-bot-bench/SpamFighter` handles data, and how a SpamFighter bot instance operated by West Coast Bot Bench processes data when installed in your Discord server.

If you self-host, fork, modify, or operate your own SpamFighter instance, you are solely responsible for your own data handling, privacy notices, retention rules, security controls, and legal compliance. This policy covers only instances operated by West Coast Bot Bench.

Discord separately processes data under Discord's own Privacy Policy and Terms of Service. SpamFighter is not affiliated with Discord Inc.

---

## 1. Who We Are

SpamFighter is operated by West Coast Bot Bench. For questions, data requests, or concerns related to this policy or a West Coast Bot Bench–operated instance, open an issue at:

**https://github.com/west-coast-bot-bench/SpamFighter/issues**

---

## 2. Summary

SpamFighter processes Discord data to detect spam, support moderation, provide audit logs, review false positives, and maintain rule-review workflows. SpamFighter does not sell personal data. SpamFighter does not use message content or user data for advertising.

The public repository is sanitized. It does not include West Coast Bot Bench production databases, private spam rules, private regexes, domain blocklists, tokens, API keys, runtime reports, or deployment-specific configuration.

---

## 3. Data SpamFighter May Process

Depending on configuration, enabled features, Discord permissions, and the channels a server grants the bot access to, SpamFighter may process the following categories of data:

**Identity and account data:**
- Discord user IDs, usernames, global names, display names, mentions, and operator-assigned labels

**Server and channel data:**
- Discord server IDs, server names, channel IDs, channel names, thread IDs, message IDs, and message links

**Message and content data:**
- Message content and edited message content visible to the bot (requires the Message Content privileged gateway intent)
- Attachment metadata, embed metadata, media indicators, filenames, and URLs contained in messages

**Moderation and operational data:**
- Spam match reasons, normalized message text, rule-review notes, and moderation outcomes
- Violation counts, reporter events, reporter confidence summaries, timestamps, and cooldown information
- Administrator command usage and configuration changes
- Audit logs, enforcement logs, error diagnostics, rate-limit observations, health status, and operational metrics

**Image data:**
- Image hashes for known-spam matching, when image-hash scanning is enabled

**AI-assisted review data (if enabled):**
- AI prompt previews, redacted report text, AI usage counters, and AI rule suggestions

SpamFighter may process current messages, edited messages, and historical messages during retroactive scans or validation scans.

**Privileged intents used:** SpamFighter uses the **Message Content** privileged gateway intent. This is required for its core spam-detection functionality. Message content may be processed for spam detection, moderation support, audit logs, false-positive review, rule-review workflows, retroactive scans, validation scans, and optional AI-assisted rule review when enabled. Message content is not used for advertising, user profiling, or third-party analytics.

---

## 4. Why Data Is Processed

SpamFighter processes data to:

- detect and respond to spam, scams, phishing, abuse, or unwanted content;
- delete matched spam when deletion is enabled;
- apply configured moderation escalation (warnings, timeouts, kicks, or bans);
- provide audit and enforcement logs to authorized server staff;
- support false-positive reports and rule-review workflows;
- test and validate spam rules against known-clean or recent message history;
- maintain violation counters and reporter confidence signals;
- troubleshoot bot reliability, permission issues, and Discord API errors;
- support optional AI-assisted rule drafting when enabled.

---

## 5. Legal Basis for Processing

For users in the European Union, United Kingdom, or other jurisdictions with similar requirements:

- **Legitimate interest:** Processing user IDs, server IDs, and message metadata is necessary for SpamFighter to perform its core spam-detection function on behalf of server administrators who have voluntarily installed the bot.
- **Legal obligation:** Some processing may be necessary to comply with applicable legal obligations.
- **Consent or appropriate notice where required:** Where optional features, such as AI-assisted review, involve additional processing beyond core functionality, operators are responsible for ensuring any required consent, notice, or other legal basis is in place before enabling those features.

---

## 6. Where Data Is Stored

Depending on deployment configuration, SpamFighter may store data in:

- local runtime files on the hosting environment;
- SQLite or Postgres databases hosted on West Coast Bot Bench infrastructure;
- configured Discord audit, enforcement, and review channels;
- log output from the hosting environment.

Data stored by West Coast Bot Bench is hosted in the United States. The public GitHub repository does not contain production runtime data.

---

## 7. AI-Assisted Review

If AI-assisted rule review is enabled, selected report content and related context may be sent to a configured AI provider (such as OpenAI) to draft or review spam rules.

SpamFighter includes redaction controls, but operators should review AI settings and prompts before enabling this feature. Message content sent for AI-assisted rule review is used to generate moderation and rule-review output, not to train SpamFighter-owned AI models. Operators must not configure AI-assisted review in a way that uses Discord message content to train AI models unless they have all permissions required by Discord and applicable law.

Do not enable AI-assisted review unless you understand and accept the AI provider's data handling terms. West Coast Bot Bench discloses when AI processing is in use.

---

## 8. Data Sharing and Third Parties

SpamFighter may share moderation information inside Discord by posting logs, reports, previews, and review messages into configured channels visible to authorized server staff.

SpamFighter may send data to third-party services only when configured to do so, such as an AI provider (e.g., OpenAI) or external database provider. In those cases, the third party's own privacy terms apply to their handling of data.

SpamFighter does not sell personal data. SpamFighter does not share personal data with advertisers or analytics platforms.

---

## 9. Data Retention

Retention depends on the operator's configuration and hosting environment.

SpamFighter includes retention settings for some rule-review reports, reporter events, attachment hash cache entries, and runtime state. Server operators should delete data that is no longer needed for moderation, security, debugging, or legal compliance.

Removing SpamFighter from a Discord server stops new processing in that server, but does not automatically delete data already stored by the operator or already posted into Discord log channels. Operators may contact West Coast Bot Bench via GitHub Issues to request deletion of data held in a West Coast Bot Bench–operated instance.

---

## 10. Security

West Coast Bot Bench takes reasonable technical and organizational measures to protect data stored by SpamFighter, including restricting access to credentials, using environment variable–based secret management, and following secure deployment practices.

Operators self-hosting SpamFighter are responsible for protecting bot tokens, API keys, databases, logs, config files, private rules, and hosting credentials. Secrets should be stored in environment variables, secret managers, or private deployment systems and must not be committed to public source control.

---

## 11. Your Rights and Choices

If you believe SpamFighter processed your data incorrectly, moderated you incorrectly, or stored data that should be reviewed or corrected, you have the following options:

- **Contact server staff** of the Discord server where the bot is installed. Server staff can review moderation actions, correct errors, and restrict or remove the bot.
- **Submit a data request or deletion request** by opening an issue at https://github.com/west-coast-bot-bench/SpamFighter/issues for West Coast Bot Bench–operated instances. Do not include private message content, tokens, personal contact details, or other sensitive information in a public GitHub issue. Request a private follow-up channel if sensitive details are needed.
- **Remove the bot from your server** (if you are a server administrator) to stop further processing in that server.

Users in the EU or UK may have additional rights under GDPR, including the right to access, rectify, erase, or port personal data, and the right to object to processing. Requests to exercise these rights may be started through GitHub Issues, but sensitive details should be handled through a private follow-up channel.

---

## 12. Children's Privacy

SpamFighter is intended for use within Discord servers and is subject to Discord's minimum age requirements (13 years old, or 16 in some EU jurisdictions). SpamFighter is not directed at children under the age of 13. West Coast Bot Bench does not knowingly collect personal data from children under 13. If we become aware that data from a child under 13 has been collected, we will take steps to delete it promptly.

Operators must not use SpamFighter to knowingly collect or process data from users in violation of Discord's rules, COPPA, or any other applicable law.

---

## 13. Changes to This Policy

This Privacy Policy may be updated as SpamFighter changes. When material changes are made, the effective date at the top of this document will be updated. Continued use of a West Coast Bot Bench–operated instance after the effective date of an updated policy constitutes acceptance of those changes.

---

*SpamFighter is not affiliated with Discord Inc. Discord's own Privacy Policy governs Discord's data processing independently of this policy.*
