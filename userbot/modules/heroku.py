# Copyright (C) 2020 Adek Maulana.
# All rights reserved.
"""
   Heroku manager for your userbot
"""

import heroku3
import aiohttp
import math

from userbot import (
    CMD_HELP,
    HEROKU_APP_NAME,
    HEROKU_API_KEY,
    BOTLOG,
    BOTLOG_CHATID
)

from userbot.events import register

heroku_api = "https://api.heroku.com"
if HEROKU_APP_NAME is not None and HEROKU_API_KEY is not None:
    Heroku = heroku3.from_key(HEROKU_API_KEY)
    app = Heroku.app(HEROKU_APP_NAME)
    heroku_var = app.config()
else:
    app = None


"""
    ConfigVars management, like get current var, set var, or delete var.
"""


@register(outgoing=True,
          pattern=r"^.(get|del) var(?: |$)(\w*)")
async def variable(var):
    exe = var.pattern_match.group(1)
    if app is None:
        await var.edit("`Please set up the HEROKU_APP_NAME variable.`")
        return False
    if exe == "get":
        await var.edit("`Getting information...`")
        variable = var.pattern_match.group(2)
        if variable != '':
            if variable in heroku_var:
                if BOTLOG:
                    await var.client.send_message(
                        BOTLOG_CHATID, "#CONFIGVAR\n\n"
                        f"`{variable}` = `{heroku_var[variable]}`\n"
                    )
                    await var.edit("`Received to BOTLOG_CHATID...`")
                    return True
                else:
                    await var.edit("`Please set BOTLOG to True...`")
                    return False
            else:
                await var.edit("`Information don't exists...`")
                return True
        else:
            configvars = heroku_var.to_dict()
            msg = ''
            if BOTLOG:
                for item in configvars:
                    msg += f"`{item}` = `{configvars[item]}`\n"
                await var.client.send_message(
                    BOTLOG_CHATID, "#CONFIGVARS\n\n"
                    f"{msg}"
                )
                await var.edit("`Received to BOTLOG_CHATID...`")
                return True
            else:
                await var.edit("`Please set BOTLOG to True...`")
                return False
    elif exe == "del":
        await var.edit("`Deleting information...`")
        variable = var.pattern_match.group(2)
        if variable == '':
            await var.edit("`Specify variable you want to delete...`")
            return False
        if variable in heroku_var:
            if BOTLOG:
                await var.client.send_message(
                    BOTLOG_CHATID, "#DELCONFIGVAR\n\n"
                    f"`{variable}`"
                )
            await var.edit("`Information deleted...`")
            del heroku_var[variable]
        else:
            await var.edit("`Information don't exists...`")
            return True


@register(outgoing=True, pattern=r'^.set var (\w*) ([\s\S]*)')
async def set_var(var):
    await var.edit("`Setting information...`")
    variable = var.pattern_match.group(1)
    value = var.pattern_match.group(2)
    if variable in heroku_var:
        if BOTLOG:
            await var.client.send_message(
                BOTLOG_CHATID, "#SETCONFIGVAR\n\n"
                f"`{variable}` = `{value}`"
            )
        await var.edit("`Information set...`")
    else:
        if BOTLOG:
            await var.client.send_message(
                BOTLOG_CHATID, "#ADDCONFIGVAR\n\n"
                f"`{variable}` = `{value}`"
            )
        await var.edit("`Information added...`")
    heroku_var[variable] = value


"""
    Check account quota, remaining quota, used quota, used app quota
"""


@register(outgoing=True, pattern=r"^.usage(?: |$)")
async def dyno_usage(dyno):
    """
        Get your account Dyno Usage
    """
    await dyno.edit("`Getting information...`")
    useragent = (
        'Mozilla/5.0 (Linux; Android 10; SM-G975F) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/81.0.4044.117 Mobile Safari/537.36'
    )
    user_id = Heroku.account().id
    headers = {
     'User-Agent': useragent,
     'Authorization': f'Bearer {HEROKU_API_KEY}',
     'Accept': 'application/vnd.heroku+json; version=3.account-quotas',
    }
    path = "/accounts/" + user_id + "/actions/get-quota"
    async with aiohttp.ClientSession() as session:
        async with session.get(heroku_api + path, headers=headers) as r:
            if r.status != 200:
                await dyno.client.send_message(
                    dyno.chat_id,
                    f"`{r.reason}`",
                    reply_to=dyno.id
                )
                await dyno.edit("`Can't get information...`")
                return False
            result = await r.json()
            quota = result['account_quota']
            quota_used = result['quota_used']

            """ - User Quota Limit and Used - """
            remaining_quota = quota - quota_used
            percentage = math.floor(remaining_quota / quota * 100)
            minutes_remaining = remaining_quota / 60
            hours = math.floor(minutes_remaining / 60)
            minutes = math.floor(minutes_remaining % 60)

            """ - User App Used Quota - """
            Apps = result['apps']
            for apps in Apps:
                if apps.get('app_uuid') == app.id:
                    AppQuotaUsed = apps.get('quota_used') / 60
                    AppPercentage = math.floor(
                        apps.get('quota_used') * 100 / quota)
                    break
            else:
                AppQuotaUsed = 0
                AppPercentage = 0

            AppHours = math.floor(AppQuotaUsed / 60)
            AppMinutes = math.floor(AppQuotaUsed % 60)

            await dyno.edit(
                 "**Dyno Usage**:\n\n"
                 f"-> `Dyno usage for`  **{app.name}**:\n"
                 f"    •  **{AppHours} hour(s), {AppMinutes} minute(s) "
                 f" -  {AppPercentage}%**\n\n"
                 "-> `Dyno hours balance`:\n"
                 f"    •  **{hours} hour(s), {minutes} minute(s)  "
                 f"-  {percentage}%**"
            )
            return True


CMD_HELP.update({
    "heroku":
    "• `.usage`\n"
    "Usage: Check Heroku dyno hours balance.\n\n"
    "• `.set var <name> <value>`\n"
    "Usage: Add new variable or update existing variable value.\n"
    "**WARNING**: After setting a variable, the bot will restarted.\n\n"
    "• `.get var` or `.get var <name>`\n"
    "Usage: Gets existing varibles. Use it only on private group!\n"
    "This returns all of your private information, please be careful!\n\n"
    "• `.del var <name>`\n"
    "Usage: Deletes existing variable.\n"
    "**WARNING**: After deleting variable, the bot will restarted."
})
