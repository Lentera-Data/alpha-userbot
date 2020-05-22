# Copyright (C) 2019 The Raphielscape Company LLC.
#
# Licensed under the Raphielscape Public License, Version 1.c (the "License");
# you may not use this file except in compliance with the License.
#
""" Userbot module containing hash and encode/decode commands. """

from subprocess import PIPE
from subprocess import run as runapp
import pybase64
from userbot import CMD_HELP
from userbot.events import register


@register(outgoing=True, pattern="^.hash (.*)")
async def gethash(hash_q):
    """ For .hash command, find the md5, sha1, sha256, sha512 of the string. """
    hashtxt_ = hash_q.pattern_match.group(1)
    hashtxt = open("hashthis.txt", "w+")
    hashtxt.write(hashtxt_)
    hashtxt.close()
    md5 = runapp(["md5sum", "hashthis.txt"], stdout=PIPE)
    md5 = md5.stdout.decode()
    md5 = md5[:-14]
    sha1 = runapp(["sha1sum", "hashthis.txt"], stdout=PIPE)
    sha1 = sha1.stdout.decode()
    sha1 = sha1[:-14]
    sha256 = runapp(["sha256sum", "hashthis.txt"], stdout=PIPE)
    sha256 = sha256.stdout.decode()
    sha256 = sha256[:-14]
    sha512 = runapp(["sha512sum", "hashthis.txt"], stdout=PIPE)
    sha512 = sha512.stdout.decode()
    sha512 = sha512[:-14]
    runapp(["rm", "hashthis.txt"], stdout=PIPE)
    ans = ("**Text:** `" + hashtxt_ + "`\n**MD5:** `" + md5 + "`\n**SHA1:** `" +
            sha1 + "`\n**SHA256:** `" + sha256 + "`\n**SHA512:** `" + sha512 + "`")
    if len(ans) > 4096:
        hashfile = open("hashes.txt", "w+")
        hashfile.write(ans)
        hashfile.close()
        await hash_q.client.send_file(
            hash_q.chat_id,
            "hashes.txt",
            reply_to=hash_q.id,
            caption="`It's too big, sending a text file instead. `")
        runapp(["rm", "hashes.txt"], stdout=PIPE)
    else:
        await hash_q.reply(ans)


@register(outgoing=True, pattern="^.base64 (en|de) (.*)")
async def endecrypt(query):
    """ For .base64 command, find the base64 encoding of the given string. """
    if query.pattern_match.group(1) == "en":
        lething = str(
            pybase64.b64encode(bytes(query.pattern_match.group(2),
                                     "utf-8")))[2:]
        await query.reply("Encoded: `" + lething[:-1] + "`")
    else:
        lething = str(
            pybase64.b64decode(bytes(query.pattern_match.group(2), "utf-8"),
                               validate=True))[2:]
        await query.reply("Decoded: `" + lething[:-1] + "`")


CMD_HELP.update({
    "hash":
    "• `.hash`\n"
    "Usage: Find the md5, sha1, sha256, sha512 of the string when written into a txt file.",
    "base64":
    "• `.base64 <en/de>`\n"
    "Usage: Find the base64 encoding/decoding of the given string."
})
