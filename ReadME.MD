# 🛡️ Velvox Security Bot

Velvox is a powerful Discord bot focused on **raid protection**, **audit logging**, and **server security** — built to help server owners secure their communities with ease.

[Invite the bot now!](https://discord.com/oauth2/authorize?client_id=1387429800053837874).

If you want to host it your self you can download the files above.

## ✨ Features

* 🔐 **Security Audits** — Use `/audit` to get a detailed DM report on risky roles, bots, AutoMod status, logging setup, 2FA enforcement, and more.
* 🚨 **Raid Protection** — Automatically detects and kicks users who:

  * Mass-delete channels
  * Mass-create or delete roles
  * Create too many webhooks
  * Ban or kick many users in a short time
* 🤖 **Bot Admin Checks** — Flags bots with full admin permissions.
* 🔨 **Blacklist Enforcement** — Instantly kicks members with blacklisted IDs.
* 📝 **Logging System** — Send all incidents to a private channel of your choice.


## 📋 Slash Commands

| Command            | Description                                     | Access           |
| ------------------ | ----------------------------------------------- | ---------------- |
| `/audit`           | DM yourself a security audit of the server      | Admin/Owner only |
| `/set_log_channel` | Set the current channel as the audit log output | Owner only       |
| `/set_protection`  | Select protection mode (Off, Audit, Strict)     | Owner only       |


## ⚙️ Setup

1. Invite the bot with required permissions (admin recommended for full functionality).
2. Use `/set_log_channel` in your desired logging channel. (Send this from the channel you want to get logs from!)
3. Run `/set_protection` to configure your protection level.
4. Run `/audit` to get a private DM report of your server’s security status.


## 🔐 Permissions Required

* `Manage Roles`
* `Kick Members`
* `View Audit Logs`
* `Send Messages` (in log channel)
* `Ensure the role of the bot is above all the general staff to ensure they can not remove it. Or mitigate the risk of a insider threat in a other way.`


## 🛡️ Protection Modes

* `Off`: No protection enabled.
* `Audit`: Only logs suspicious activity.
* `Strict`: Automatically kicks users who perform too many risky actions.


## 💡 Notes

* All checks run automatically, even if slash commands are never used.
* The bot does not store personal data permanently and only processes in-server events in memory or local JSON configs.


## 📝 License

This project is open-source under the [GNU GPL v3.0](https://github.com/Velvox/Velvox-Anti-Raid.py/blob/main/LICENSE)
