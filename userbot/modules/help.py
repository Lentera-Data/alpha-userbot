# Copyright (C) 2019 The Raphielscape Company LLC.
#
# Licensed under the Raphielscape Public License, Version 1.c (the "License");
# you may not use this file except in compliance with the License.
#
""" Userbot help command """

from userbot import CMD_HELP
from userbot.events import register


@register(outgoing=True, pattern="^.help(?: |$)(.*)")
async def help(event):
    """ For .help command,"""
    args = event.pattern_match.group(1).lower()
    if args:
        if args in CMD_HELP:
            await event.edit(str(CMD_HELP[args]))
        else:
            await event.edit("Please specify a valid module name.")
    else:
        sdata = []
        string = ""
        for i in CMD_HELP:
            sdata.append(i)
            sdata.sort(key=str.lower)
        for i in sdata:
            string += f"`{str(i)}`, "
        string = string[:-2]
        await event.edit(
            "**Please specify which module you want help for!**\n"
            "Usage: `.help <module name>`\n\n"
            f"{string}"
        )
