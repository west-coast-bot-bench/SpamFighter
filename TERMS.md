# SpamFighter Terms of Service

Effective date: June 13, 2026

These Terms of Service ("Terms") apply to the public SpamFighter Discord bot software published at `west-coast-bot-bench/SpamFighter` and to any SpamFighter bot instance operated by West Coast Bot Bench ("we," "us," or "our").

If you self-host, fork, modify, or operate your own SpamFighter instance, you are solely responsible for your own deployment, server rules, moderation decisions, user notices, terms, privacy policy, and legal compliance.

---

## 1. What SpamFighter Does

SpamFighter is a Discord moderation bot designed to help server staff identify, log, review, and respond to spam and abuse.

Depending on configuration and Discord permissions, SpamFighter may:

- scan message content, edited message content, attachments, embeds, and message metadata available to the bot;
- scan recent channel history for retroactive spam review;
- scan text channels, threads, and voice-channel text chats where Discord exposes message history to the bot;
- log suspected spam, rule-review events, and moderation actions;
- delete messages when deletion is enabled;
- track server-specific violation counts;
- timeout, kick, or ban users when escalation thresholds are met and escalation is enabled by server administrators;
- allow administrators to test messages, configure rules, reload rules, review false positives, and manage moderation settings;
- optionally use AI-assisted rule review when configured by the operator.

SpamFighter uses the **Message Content** privileged gateway intent. This intent is required for its core spam-detection function. SpamFighter does not use message content for advertising, profiling, or any purpose other than spam detection and moderation support.

The public repository is a sanitized source export. It does not include West Coast Bot Bench production spam rules, private regexes, domain blocklists, secrets, databases, runtime reports, API keys, tokens, or deployment-specific configuration.

---

## 2. Acceptance

By adding, configuring, operating, self-hosting, or interacting with a SpamFighter instance, you agree to be bound by these Terms to the extent they apply to your role and that instance.

You must also comply with:

- [Discord's Terms of Service](https://discord.com/terms), [Community Guidelines](https://discord.com/guidelines), [Developer Terms of Service](https://support-dev.discord.com/hc/en-us/articles/8562894815383), and [Developer Policy](https://support-dev.discord.com/hc/en-us/articles/8563934450327);
- the rules of any Discord server where SpamFighter is installed;
- all applicable laws and regulations.

If you do not agree to these Terms, do not add, configure, or use SpamFighter.

---

## 3. Eligibility

SpamFighter is intended for use by individuals who are at least 13 years of age (or the applicable minimum age in their jurisdiction). By using SpamFighter, you represent that you meet the minimum age requirement and have the authority to bind yourself or, if you are a server administrator adding SpamFighter to a server, your server community to these Terms.

---

## 4. Server Administrator Responsibilities

Server administrators who add SpamFighter to a server are responsible for:

- granting only the Discord permissions SpamFighter needs to function;
- configuring audit and enforcement channels appropriately to protect member privacy;
- reviewing dry-run behavior before enabling message deletion or escalation actions;
- reviewing moderation logs and false-positive reports on an ongoing basis;
- configuring private spam rules, regexes, blocklists, and AI settings responsibly;
- informing server members about SpamFighter's presence and data processing when required by law, platform policy, or server rules;
- ensuring their use of SpamFighter complies with Discord's Developer Policy and all applicable privacy laws.

---

## 5. Moderation Actions and Accuracy

SpamFighter is an automated moderation aid, not a guarantee of accurate moderation.

SpamFighter may produce false positives or false negatives. Server staff are solely responsible for reviewing configuration, appeals, logs, and enforcement outcomes and for correcting any errors.

If enforcement is enabled, SpamFighter may delete messages or apply timeouts, kicks, or bans according to the configured thresholds and Discord role hierarchy. **Test in dry-run mode before enabling enforcement in a live server.** West Coast Bot Bench is not responsible for moderation errors resulting from misconfiguration or from inherent limitations of automated detection.

---

## 6. Prohibited Use

You may not use SpamFighter to:

- violate Discord's Terms of Service, Community Guidelines, Developer Terms, Developer Policy, rate limits, or technical restrictions;
- harass, target, discriminate against, or retaliate against users;
- collect, expose, sell, or otherwise misuse private user data;
- log more data than is reasonably necessary for moderation, security, debugging, or abuse prevention;
- bypass Discord permissions, role hierarchy, or security controls;
- operate deceptive, malicious, spam, phishing, surveillance, or abusive automation;
- use Discord message content processed by SpamFighter to train AI models unless you have all permissions required by Discord and applicable law;
- knowingly process data from children under 13 (or the applicable minimum age in their jurisdiction);
- violate any applicable law or regulation.

We reserve the right to remove SpamFighter from any server or terminate access to a West Coast Bot Bench–operated instance if we believe these Terms have been violated.

---

## 7. Open Source License

The public SpamFighter source code is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See `LICENSE` for the full license text.

The GPL-3.0 license covers the public source code in this repository. It does not grant access to private production configuration, spam rules, regexes, blocklists, databases, runtime logs, credentials, or other non-public deployment data belonging to West Coast Bot Bench.

---

## 8. Privacy

SpamFighter's collection and use of data is described in the [SpamFighter Privacy Policy](PRIVACY.md). By using SpamFighter, you acknowledge that you have read and understood the Privacy Policy.

Server administrators are responsible for ensuring their server members are made aware of SpamFighter's data practices when required by law or platform policy.

---

## 9. Availability, Support, and Changes

SpamFighter and any West Coast Bot Bench–operated instance are provided on an as-is, as-available basis. Features may change, break, or be removed at any time without notice.

West Coast Bot Bench may update these Terms, update the software, pause a hosted bot instance, remove it from a server, or stop operating an instance at any time. Continued use of SpamFighter after updated Terms are posted constitutes acceptance of the updated Terms.

Support is provided on a best-effort basis and is not guaranteed.

---

## 10. No Warranty and Limitation of Liability

**SpamFighter is provided without warranty of any kind, express or implied**, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement. See the GPL-3.0 license text for the full warranty disclaimer.

To the maximum extent permitted by applicable law, West Coast Bot Bench shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising from your use of or inability to use SpamFighter, including any errors in automated moderation, loss of messages, unintended bans or timeouts, or unauthorized access to stored data.

You are responsible for reviewing and accepting the risks of automated moderation before enabling enforcement features.

---

## 11. Governing Law

These Terms are governed by the laws of the State of California, United States, without regard to conflict of law principles. Any disputes arising from these Terms that are not resolved informally shall be submitted to the courts of competent jurisdiction in California.

If you are located in the European Union, this does not affect any mandatory consumer rights you may have under local law.

---

## 12. Contact

For questions, abuse reports, data requests, takedown requests, or security concerns related to this public repository or a West Coast Bot Bench–operated instance, open an issue at the link below. Do not post private message content, credentials, personal contact details, or other sensitive information in a public GitHub issue. Request a private follow-up channel if sensitive details are needed.

**https://github.com/west-coast-bot-bench/SpamFighter/issues**

---

*SpamFighter is not affiliated with Discord Inc. Use of SpamFighter is subject to Discord's own Terms of Service and policies independently of these Terms.*
