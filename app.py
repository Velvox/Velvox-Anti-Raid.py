import discord
from discord.ext import commands, tasks
from discord import app_commands, Embed, Interaction, SelectOption
from discord.ui import View, Select
import json
import asyncio
import dotenv

# Load .env config
config = dotenv.dotenv_values(".env")
TOKEN = config.get("TOKEN")
CHANNEL_DELETE_LIMIT = int(config.get("CHANNEL_DELETE_LIMIT", 5))
CHANNEL_DELETE_WINDOW = float(config.get("CHANNEL_DELETE_WINDOW", 2))
TICKET_BOT_IDS = json.loads(config.get("TICKET_BOT_IDS", "[]"))
ROLE_CREATE_LIMIT = int(config.get("ROLE_CREATE_LIMIT", 3))
ROLE_CREATE_WINDOW = float(config.get("ROLE_CREATE_WINDOW", 5))
ROLE_DELETE_LIMIT = int(config.get("ROLE_DELETE_LIMIT", 3))
ROLE_DELETE_WINDOW = float(config.get("ROLE_DELETE_WINDOW", 5))
WEBHOOK_CREATE_LIMIT = int(config.get("WEBHOOK_CREATE_LIMIT", 2))
WEBHOOK_CREATE_WINDOW = float(config.get("WEBHOOK_CREATE_WINDOW", 5))
BAN_LIMIT = int(config.get("BAN_LIMIT", 3))
BAN_WINDOW = float(config.get("BAN_WINDOW", 5))
KICK_LIMIT = int(config.get("KICK_LIMIT", 3))
KICK_WINDOW = float(config.get("KICK_WINDOW", 5))
DEBUG = float(config.get("DEBUG", False))



intents = discord.Intents.default()
intents.members = True

bot = commands.Bot(command_prefix=lambda bot, msg: [], intents=intents)

channel_delete_logs = {}
role_create_logs = {}
role_delete_logs = {}
webhook_create_logs = {}
member_ban_logs = {}

settings_file = "server_settings.json"
banned_ids_file = "banned_ids.json"

# Helper functions

def load_json(filename):
    try:
        with open(filename, "r") as f:
            print(f"[INFO] Loading {filename}...")
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load {filename}: {e}")
        return {}

def save_json(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
            print(f"[INFO] Saved data to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save {filename}: {e}")

def get_guild_setting(guild_id):
    settings = load_json(settings_file)
    return settings.get(str(guild_id), {}).get("protection_level", "off")

def set_guild_setting(guild_id, level):
    if DEBUG:
        print(f"[INFO] Setting protection level for guild {guild_id} to '{level}'")

    settings = load_json(settings_file)
    current = settings.get(str(guild_id), {})
    current["protection_level"] = level
    settings[str(guild_id)] = current
    save_json(settings_file, settings)

def set_log_channel(guild_id, channel_id):
    if DEBUG:
        print(f"[INFO] Setting log channel for guild {guild_id} to {channel_id}")
    
    settings = load_json(settings_file)
    if str(guild_id) not in settings:
        settings[str(guild_id)] = {}
    settings[str(guild_id)]["log_channel"] = channel_id
    save_json(settings_file, settings)

def check_action_spam(guild_id, user_id, action_log, window, limit):
    now = asyncio.get_event_loop().time()
    key = f"{guild_id}:{user_id}"
    record = action_log.setdefault(key, [])
    record.append(now)
    action_log[key] = [t for t in record if now - t <= window]
    return len(action_log[key]) >= limit

# Raid protection: Channel deletions
@bot.event
async def on_guild_channel_delete(channel):
    if DEBUG:
        print(f"[INFO] Channel deleted: {channel.name} ({channel.id})")
    
    guild_id = str(channel.guild.id)
    protection_level = get_guild_setting(guild_id)
    if DEBUG:
        print(f"[INFO] Guild protection level: {protection_level}")
    if protection_level == "off":
        return

    audit_logs = [entry async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete)]
    if not audit_logs:
        print("[ERROR] No audit logs found for channel deletion")
        return

    entry = audit_logs[0]
    executor = entry.user
    if DEBUG:
        print(f"Executor of deletion: {executor} ({executor.id})")

    if executor.bot and executor.id in TICKET_BOT_IDS:
        print("[INFO] Executor is a ticket bot, ignoring.")
        return

    now = asyncio.get_event_loop().time()
    record = channel_delete_logs.setdefault(guild_id, [])
    record.append((executor.id, now))
    record = [entry for entry in record if now - entry[1] <= CHANNEL_DELETE_WINDOW]
    channel_delete_logs[guild_id] = record

    deletions = [uid for uid, _ in record if uid == executor.id]
    count = len(deletions)
    if DEBUG:
        print(f"{count} deletions by {executor.id} within time window")

    settings = load_json(settings_file)
    log_channel_id = settings.get(guild_id, {}).get("log_channel")
    log_channel = channel.guild.get_channel(log_channel_id) if log_channel_id else None

    if log_channel and protection_level in ("audit", "strict"):
        embed = discord.Embed(
            title="Channel Deletion Detected",
            description=f"User {executor.mention} (`{executor.id}`) deleted {count} channels in {CHANNEL_DELETE_WINDOW} seconds.",
            color=discord.Color.orange(),
            timestamp=discord.utils.utcnow()
        )
        await log_channel.send(embed=embed)
        if DEBUG:
            print(f"Logged deletion to channel {log_channel.id}")

    if protection_level == "strict" and count >= CHANNEL_DELETE_LIMIT:
        try:
            await channel.guild.kick(executor, reason="[RAID PROTECTION] Mass channel deletion detected.")
            if DEBUG:
                print(f"Kicked user {executor.id} for mass deletions")
            if log_channel:
                embed = discord.Embed(
                    title="User Kicked",
                    description=f"User {executor.mention} (`{executor.id}`) was kicked for mass channel deletion.",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to kick: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"{executor.mention} Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)

@bot.event
async def on_guild_role_create(role):
    if DEBUG:
        print(f"Role created: {role.name} ({role.id}) in guild {role.guild.id}")
    guild_id = str(role.guild.id)
    protection_level = get_guild_setting(guild_id)
    if protection_level == "off":
        return

    audit_logs = [entry async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_create)]
    if not audit_logs:
        print("[ERROR] No audit logs for role creation.")
        return

    entry = audit_logs[0]
    executor = entry.user
    if DEBUG:
        print(f"Executor of role creation: {executor} ({executor.id})")

    settings = load_json(settings_file)
    log_channel_id = settings.get(guild_id, {}).get("log_channel")
    log_channel = role.guild.get_channel(log_channel_id) if log_channel_id else None

    count_triggered = check_action_spam(guild_id, executor.id, role_create_logs, ROLE_CREATE_WINDOW, ROLE_CREATE_LIMIT)

    if log_channel and protection_level in ("audit", "strict"):
        embed = discord.Embed(
            title="Role Created",
            description=f"User {executor.mention} (`{executor.id}`) created role `{role.name}`.",
            color=discord.Color.purple(),
            timestamp=discord.utils.utcnow()
        )
        await log_channel.send(embed=embed)

    if protection_level == "strict" and count_triggered:
        try:
            await role.guild.kick(executor, reason="[RAID PROTECTION] Mass role creation")
            if DEBUG:
                print(f"Kicked user {executor.id} for mass role creation")
            if log_channel:
                embed = discord.Embed(
                    title="User Kicked",
                    description=f"{executor.mention} was kicked for creating too many roles quickly.",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to kick: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"{executor.mention} Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)

# Webhook creation monitor
@bot.event
async def on_webhooks_update(channel):
    if DEBUG:
        print(f"Webhook update in channel: {channel.name} ({channel.id})")
    guild_id = str(channel.guild.id)
    protection_level = get_guild_setting(guild_id)
    if protection_level == "off":
        return

    audit_logs = [entry async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create)]
    if not audit_logs:
        print("[ERROR] No audit logs for webhook creation.")
        return

    entry = audit_logs[0]
    executor = entry.user
    if DEBUG:
        print(f"Executor of webhook creation: {executor} ({executor.id})")

    settings = load_json(settings_file)
    log_channel_id = settings.get(guild_id, {}).get("log_channel")
    log_channel = channel.guild.get_channel(log_channel_id) if log_channel_id else None

    count_triggered = check_action_spam(guild_id, executor.id, webhook_create_logs, WEBHOOK_CREATE_WINDOW, WEBHOOK_CREATE_LIMIT)

    if log_channel and protection_level in ("audit", "strict"):
        embed = discord.Embed(
            title="Webhook Created",
            description=f"User {executor.mention} (`{executor.id}`) created a webhook in #{channel.name}.",
            color=discord.Color.gold(),
            timestamp=discord.utils.utcnow()
        )
        await log_channel.send(embed=embed)

    if protection_level == "strict" and count_triggered:
        try:
            await channel.guild.kick(executor, reason="[RAID PROTECTION] Mass webhook creation")
            if DEBUG:
                print(f"Kicked user {executor.id} for webhook creation spam")
            if log_channel:
                embed = discord.Embed(
                    title="User Kicked",
                    description=f"{executor.mention} was kicked for creating too many webhooks quickly.",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to kick: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"{executor.mention} Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)

@bot.event
async def on_guild_role_delete(role):
    if DEBUG:
        print(f"Role deleted: {role.name} ({role.id}) in guild {role.guild.id}")
    guild_id = str(role.guild.id)
    protection_level = get_guild_setting(guild_id)
    if protection_level == "off":
        return

    audit_logs = [entry async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete)]
    if not audit_logs:
        print("[ERROR] No audit logs for role deletion.")
        return

    entry = audit_logs[0]
    executor = entry.user
    if DEBUG:
        print(f"Executor of role deletion: {executor} ({executor.id})")

    count_triggered = check_action_spam(guild_id, executor.id, role_delete_logs, ROLE_DELETE_WINDOW, ROLE_DELETE_LIMIT)

    settings = load_json(settings_file)
    log_channel_id = settings.get(guild_id, {}).get("log_channel")
    log_channel = role.guild.get_channel(log_channel_id) if log_channel_id else None

    if log_channel and protection_level in ("audit", "strict"):
        embed = discord.Embed(
            title="Role Deleted",
            description=f"User {executor.mention} (`{executor.id}`) deleted role `{role.name}`.",
            color=discord.Color.orange(),
            timestamp=discord.utils.utcnow()
        )
        await log_channel.send(embed=embed)

    if protection_level == "strict" and count_triggered:
        try:
            await role.guild.kick(executor, reason="[RAID PROTECTION] Mass role deletion")
            if DEBUG:
                print(f"Kicked user {executor.id} for role delete spam")
            if log_channel:
                embed = discord.Embed(
                    title="User Kicked",
                    description=f"{executor.mention} was kicked for deleting too many roles quickly.",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to kick: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"{executor.mention} Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)


# Raid protection: ID banning
@bot.event
async def on_member_join(member):
    banned_ids = load_json(banned_ids_file)
    if str(member.id) in banned_ids:
        try:
            await member.kick(reason="Globally blacklisted ID")
            if DEBUG:
                print(f"Kicked banned user: {member.id}")

            # Log if a channel is configured
            guild_id = str(member.guild.id)
            settings = load_json(settings_file)
            log_channel_id = settings.get(guild_id, {}).get("log_channel")
            if log_channel_id:
                log_channel = member.guild.get_channel(log_channel_id)
                if log_channel:
                    embed = discord.Embed(
                        title="User Kicked (Banned ID)",
                        description=f"{member.mention} (`{member.id}`) was kicked for being on the banned ID list.",
                        color=discord.Color.dark_red(),
                        timestamp=discord.utils.utcnow()
                    )
                    await log_channel.send(embed=embed)

        except Exception as e:
            print(f"[ERROR] Failed to kick banned user: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"<@{member.id}> ({member.id}) Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)

@bot.event
async def on_member_ban(guild, user):
    if DEBUG:
        print(f"Ban detected in guild {guild.id}: {user.id}")
    guild_id = str(guild.id)
    protection_level = get_guild_setting(guild_id)
    if protection_level == "off":
        return

    audit_logs = [entry async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban)]
    if not audit_logs:
        return

    entry = audit_logs[0]
    executor = entry.user
    if DEBUG:
        print(f"Executor of ban: {executor} ({executor.id})")

    count_triggered = check_action_spam(guild_id, executor.id, member_ban_logs, BAN_WINDOW, BAN_LIMIT)

    settings = load_json(settings_file)
    log_channel_id = settings.get(guild_id, {}).get("log_channel")
    log_channel = guild.get_channel(log_channel_id) if log_channel_id else None

    if log_channel and protection_level in ("audit", "strict"):
        embed = discord.Embed(
            title="User Banned Another Member",
            description=f"{executor.mention} banned {user.mention} (`{user.id}`)",
            color=discord.Color.orange(),
            timestamp=discord.utils.utcnow()
        )
        await log_channel.send(embed=embed)

    if protection_level == "strict" and count_triggered:
        try:
            await guild.kick(executor, reason="[RAID PROTECTION] Mass banning users")
            if DEBUG:
                print(f"Kicked {executor.id} for mass bans")
            if log_channel:
                embed = discord.Embed(
                    title="User Kicked",
                    description=f"{executor.mention} was kicked for banning multiple users in a short time.",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to kick: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"{executor.mention} Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)

@bot.event
async def on_member_remove(member):
    guild = member.guild
    guild_id = str(guild.id)
    protection_level = get_guild_setting(guild_id)
    if protection_level == "off":
        return

    audit_logs = [entry async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.kick)]
    if not audit_logs:
        return

    entry = audit_logs[0]
    if entry.target.id != member.id:
        return

    executor = entry.user
    print(f"{executor} kicked {member}")

    count_triggered = check_action_spam(guild_id, executor.id, member_ban_logs, KICK_WINDOW, KICK_LIMIT)

    settings = load_json(settings_file)
    log_channel_id = settings.get(guild_id, {}).get("log_channel")
    log_channel = guild.get_channel(log_channel_id) if log_channel_id else None

    if log_channel and protection_level in ("audit", "strict"):
        embed = discord.Embed(
            title="User Kicked Another Member",
            description=f"{executor.mention} kicked {member.mention} (`{member.id}`)",
            color=discord.Color.orange(),
            timestamp=discord.utils.utcnow()
        )
        await log_channel.send(embed=embed)

    if protection_level == "strict" and count_triggered:
        try:
            await guild.kick(executor, reason="[RAID PROTECTION] Mass kicks")
            if DEBUG:
                print(f"Kicked {executor.id} for mass kicking")
            if log_channel:
                embed = discord.Embed(
                    title="User Kicked",
                    description=f"{executor.mention} was kicked for kicking multiple users in a short time.",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to kick: {e}")
            if log_channel:
                errembed = discord.Embed(
                    title="Could not kick the user",
                    description=f"{executor.mention} Could not be kicked for the following reason `{e}`",
                    color=discord.Color.red(),
                    timestamp=discord.utils.utcnow()
                )
                await log_channel.send(embed=errembed)

class ProtectionSelect(Select):
    def __init__(self, guild_id):
        options = [
            SelectOption(label="Off", value="off", description="Disable protection."),
            SelectOption(label="Audit", value="audit", description="Log actions only."),
            SelectOption(label="Strict", value="strict", description="Take strict actions."),
        ]
        super().__init__(placeholder="Select protection level...", min_values=1, max_values=1, options=options)
        self.guild_id = guild_id

    async def callback(self, interaction: Interaction):
        level = self.values[0]
        print(f"{interaction.user} set protection level to {level} in guild {self.guild_id}")
        set_guild_setting(self.guild_id, level)
        embed = Embed(title="Protection Level Updated", description=f"New level: **{level}**", color=discord.Color.green())
        await interaction.response.edit_message(embed=embed, view=None)

class ProtectionView(View):
    def __init__(self, guild_id):
        super().__init__(timeout=None)
        self.add_item(ProtectionSelect(guild_id))

@bot.tree.command(name="set_protection", description="Set raid protection level.")
async def set_protection(interaction: Interaction):
    if interaction.user != interaction.guild.owner:
        await interaction.response.send_message(embed=Embed(title="🚫 Access Denied", description="Only the server owner can use this command.", color=discord.Color.red()), ephemeral=True)
        return
    embed = Embed(title="Set Protection Level", description="Choose how strict the protection should be.", color=discord.Color.blue())
    await interaction.response.send_message(embed=embed, view=ProtectionView(interaction.guild.id), ephemeral=True)

@bot.tree.command(name="set_log_channel", description="Set log channel for audit events.")
async def set_log_channel_cmd(interaction: Interaction):
    if interaction.user != interaction.guild.owner:
        await interaction.response.send_message(
            embed=Embed(
                title="Access Denied",
                description="Only the server owner can use this command.",
                color=discord.Color.red(),
            ),
            ephemeral=True
        )
        return

    set_log_channel(interaction.guild.id, interaction.channel.id)
    embed = Embed(
        title="Log Channel Set",
        description=f"Audit logs will be sent to this channel.",
        color=discord.Color.blue(),
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="audit", description="Run a security audit on this server (DM only)")
async def audit_server(interaction: Interaction):
    if not (interaction.user == interaction.guild.owner or interaction.user.guild_permissions.administrator):
        await interaction.response.send_message(
            embed=Embed(
                title="Access Denied",
                description="Only the server owner or an admin can run a security audit.",
                color=discord.Color.red()
            ),
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    guild = await interaction.client.fetch_guild(interaction.guild.id)
    results = []
    remediation = set()  # Use set to avoid duplicates

    # Role permission audit
    risky_perms = [
        "administrator", "manage_guild", "ban_members", "kick_members",
        "manage_channels", "manage_roles", "manage_webhooks", "manage_emojis"
    ]
    roles_with_risky = []
    roles_with_risky_perms = {}  # role: list of perms

    for role in guild.roles:
        if role.is_default():
            continue
        triggered_perms = []
        for perm in risky_perms:
            if getattr(role.permissions, perm):
                triggered_perms.append(perm)
        if triggered_perms:
            roles_with_risky.append(role)
            roles_with_risky_perms[role] = triggered_perms

    if roles_with_risky:
        results.append(f"🔐❗ **{len(roles_with_risky)} roles** have risky permissions:")
        remediation.add("➡️ Consider reducing permissions like `administrator`, `manage_guild`, or `ban_members` unless necessary.")
        for r in roles_with_risky[:10]:
            perms_list = ", ".join(f"`{p}`" for p in roles_with_risky_perms[r])
            results.append(f"  • `{r.name}` ({r.id}) — Permissions: {perms_list}")
    else:
        results.append("🔐✅ No overly permissive roles detected.")

    # @everyone permissions
    everyone_role = guild.default_role
    dangerous_perms = ["mention_everyone", "manage_channels", "ban_members", "administrator"]
    for perm in dangerous_perms:
        if getattr(everyone_role.permissions, perm):
            results.append(f"👥❗ `@everyone` has `{perm}` permission.")
            remediation.add("➡️ Remove risky permissions from `@everyone` to prevent abuse.")
            break
    else:
        results.append("👥✅ `@everyone` role has limited permissions.")

    # Admin bot scan
    admin_bots = [m for m in guild.members if m.bot and m.guild_permissions.administrator]
    if admin_bots:
        results.append(f"🤖❗ {len(admin_bots)} bots have `Administrator` permission:")
        remediation.add("➡️ Ensure only trusted bots have Administrator access.")
        for bot in admin_bots[:10]:
            results.append(f"    • `{bot.display_name}` (`{bot.id}`)")
    else:
        results.append("🤖✅ No bots with `Administrator` permission.")


    # AutoMod audit
    try:
        automod_rules = await guild.fetch_auto_moderation_rules()
        if automod_rules:
            results.append(f"🛡️✅ AutoMod has **{len(automod_rules)} rules** configured.")
        else:
            results.append("🛡️⚠️ **No AutoMod rules configured.**")
            remediation.add("➡️ Set up AutoMod or trusted bots like MEE6/Sapphire.")
    except Exception:
        results.append("🛡️⚠️ Could not fetch AutoMod rules.")

    # 2FA check
    mfa_level = guild.mfa_level
    if mfa_level.value == 1:
        results.append("🔐✅ 2FA for moderation is enforced.")
    else:
        results.append("🔐❗ **2FA for moderation is NOT enforced.**")
        remediation.add("➡️ Enable 2FA in Server Settings ➡️ Safety Setup ➡️ Permissions ➡️ Require 2FA for moderator actions.")
    # Verification level
    v_level = guild.verification_level
    if v_level in (discord.VerificationLevel.high, discord.VerificationLevel.highest):
        results.append(f"📲✅ Verification level is `{v_level.name}` (High or Highest).")
    else:
        results.append(f"📲❗ Verification level is `{v_level.name}`. Consider increasing it.")
        remediation.add("➡️ Set verification level to High or Highest for better protection.")

    # Log channel check
    settings = load_json(settings_file)
    log_channel_id = settings.get(str(guild.id), {}).get("log_channel")
    if log_channel_id:
        results.append(f"📄✅ Log channel set: <#{log_channel_id}>")
        log_channel = guild.get_channel(log_channel_id)
        if log_channel and not log_channel.permissions_for(guild.default_role).read_messages:
            results.append("🔒✅ Log channel is private.")
        else:
            results.append("🔒⚠️ Log channel is public. Restrict it.")
    else:
        results.append("📄⚠️ No log channel set.")
        remediation.add("➡️ Use `/set_log_channel` to configure one.")

    # Embed Construction
    embed = Embed(
        title=f"🔎 Security Audit: {guild.name}",
        color=discord.Color.blurple(),
        timestamp=discord.utils.utcnow()
    )

    embed.description = (
        "**Role & Permission Audit**\n"
        + "\n".join(
            line for line in results
            if (
                (line.startswith("🔐❗") or line.startswith("🔐✅"))
                and "2FA" not in line  # exclude all 2FA lines regardless of formatting
            )
            or line.startswith("  • ")
        )
        + "\n\n**@everyone & Bot Roles**\n"
        + "\n".join(
            line for line in results
            if line.startswith("👥")
            or line.startswith("🤖")
            or line.startswith("    •")
        )

        + "\n\n**Moderation Security**\n"
        + "\n".join(line for line in results if "2FA" in line)  # put all 2FA lines here
        + "\n\n**Verification Level**\n"
        + "\n".join(line for line in results if line.startswith("📲"))
        + "\n\n**AutoMod & Verification**\n"
        + "\n".join(line for line in results if line.startswith("🛡️"))
        + "\n\n**Logging Configuration**\n"
        + "\n".join(line for line in results if line.startswith("📄") or line.startswith("🔒"))
    )

    if remediation:
        embed.add_field(
            name="🧩 Recommendations",
            value="\n".join(sorted(remediation)),  # sorted for readability
            inline=False
        )

    embed.add_field(
        name="📘 Legend",
        value=(
            "✅ = Good / Secure\n"
            "🛡️ = Optional feature\n"
            "⚠️ = Needs attention\n"
            "❗ = Urgent/Dangerous\n"
            "**FAT TEXT** = CHANGE NOW!"
        ),
        inline=False
    )

    try:
        await interaction.user.send(embed=embed)
        await interaction.followup.send(
            embed=Embed(
                title="Audit Sent",
                description="✅ Security audit has been sent to your DMs.",
                color=discord.Color.green()
            ),
            ephemeral=True
        )
    except discord.Forbidden:
        await interaction.followup.send(
            embed=Embed(
                title="DM Failed",
                description="❌ I couldn't send you the audit via DM. Please allow DMs from server members.",
                color=discord.Color.red()
            ),
            ephemeral=True
        )


@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"Logged in as {bot.user}")
    banned_ids = load_json(banned_ids_file)
    if isinstance(banned_ids, dict):
        all_banned = []
        for ids in banned_ids.values():
            all_banned.extend(ids)
    else:
        all_banned = banned_ids
    print("Last 10 banned IDs:")
    for bid in all_banned[-10:]:
        print(bid)
    print(f"Bot started successfully")

bot.run(TOKEN)
