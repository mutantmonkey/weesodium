# encoding: utf-8
#
# weesodium: encrypt messages in a channel with libsodium
# DO NOT YET RELY ON THIS SCRIPT FOR STRONG SECURITY, AS IT IS CURRENTLY
# VULNERABLE TO REPLAY ATTACKS!
#
# Copyright (c) 2014 mutantmonkey
#
# Portions based upon weechat-otr:
# Copyright (c) 2012-2014 Matthew M. Boedicker <matthewm@boedicker.org>
#                         Nils Görs <weechatter@arcor.de>
#                         Daniel "koolfy" Faucon <koolfy@koolfy.be>
#                         Felix Eckhofer <felix@tribut.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import base64
import hashlib
import libnacl.secret
import shlex
import sys
import weechat

SCRIPT_NAME = 'weesodium'
SCRIPT_AUTHOR = 'mutantmonkey'
SCRIPT_VERSION = '20141029'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = "encrypt messages in a channel with libsodium"

IRC_SANITIZE_TABLE = dict((ord(char), None) for char in '\n\r\x00')
channel_keys = {}


def encrypt(msg, key, length=None):
    if length is not None and len(msg) < length:
        msg += b'\x00' * (length - len(msg))

    box = libnacl.secret.SecretBox(key)
    ctxt = box.encrypt(msg)
    return base64.b64encode(ctxt)


def decrypt(ctxt, key):
    ctxt = base64.b64decode(ctxt)
    box = libnacl.secret.SecretBox(key)
    msg = box.decrypt(ctxt)
    msg = msg.rstrip(b'\x00')
    return msg


def parse_privmsg(message):
    weechat_result = weechat.info_get_hashtable('irc_message_parse',
                                                {'message': message})
    if weechat_result['command'].upper() == 'PRIVMSG':
        target, text = weechat_result['arguments'].split(' ', 1)
        if text.startswith(':'):
            text = text[1:]

        result = {
            'from': weechat_result['host'].decode('utf-8'),
            'to': target,
            'text': text,
        }

        if target[0] in ('#', '&', '!', '+'):
            result['to_channel'] = target
            result['to_nick'] = None
        else:
            result['to_channel'] = None
            result['to_nick'] = target

        return result
    else:
        raise Exception("Failed parsing PRIVMSG")


def irc_sanitize(msg):
    if sys.version_info.major >= 3:
        msg = str(msg)
    else:
        msg = unicode(msg)

    return msg.translate(IRC_SANITIZE_TABLE)


def irc_in_privmsg_build(fromm, to, msg):
    return ":{fromm} PRIVMSG {to} :{msg}".format(
        fromm=irc_sanitize(fromm),
        to=irc_sanitize(to),
        msg=irc_sanitize(msg))


def irc_out_privmsg_build(to, msg):
    return "PRIVMSG {to} :{msg}".format(
        to=irc_sanitize(to),
        msg=irc_sanitize(msg))


def get_buffer_info(buf):
    server = weechat.buffer_get_string(buf, b'localvar_server').decode('utf-8')
    channel = weechat.buffer_get_string(buf, b'localvar_channel').decode(
        'utf-8')
    return server, channel


def command_cb(data, buf, args):
    try:
        args = shlex.split(args)
    except:
        return weechat.WEECHAT_RC_ERROR

    if len(args) == 2 and args[0] == b'enable':
        server, channel = get_buffer_info(buf)
        key = hashlib.sha256(args[1]).digest()

        channel_keys['{0}.{1}'.format(server, channel)] = key

        weechat.prnt(buf, "This conversation is now encrypted.")
        weechat.bar_item_update(SCRIPT_NAME)

        return weechat.WEECHAT_RC_OK
    elif len(args) == 1 and args[0] == b'disable':
        server, channel = get_buffer_info(buf)
        del channel_keys['{0}.{1}'.format(server, channel)]

        weechat.prnt(buf, "This conversation is no longer encrypted.")
        weechat.bar_item_update(SCRIPT_NAME)

        return weechat.WEECHAT_RC_OK
    else:
        return weechat.WEECHAT_RC_ERROR


def in_privmsg_cb(data, modifier, modifier_data, string):
    result = parse_privmsg(string)
    if result['to_channel'] is not None:
        dict_key = '{0}.{1}'.format(modifier_data, result['to_channel'])
        if dict_key in channel_keys:
            key = channel_keys[dict_key]

            try:
                result['text'] = decrypt(result['text'], key)
            except:
                result['text'] = "Unable to decrypt: {}".format(result['text'])

            return irc_in_privmsg_build(result['from'], result['to'],
                                        result['text'])

    return string


def out_privmsg_cb(data, modifier, modifier_data, string):
    result = parse_privmsg(string)
    if result['to_channel'] is not None:
        dict_key = '{0}.{1}'.format(modifier_data, result['to_channel'])
        if dict_key in channel_keys:
            key = channel_keys[dict_key]

            # math.ceil(384 / 3) * 4 = 512
            max_length = 300 - libnacl.crypto_secretbox_NONCEBYTES \
                - libnacl.crypto_secretbox_MACBYTES
            if len(result['text']) > max_length:
                # segment messages larger than max_length
                out = ""
                splits = 1 + (len(result['text']) // max_length)
                for i in range(0, splits):
                    msg = encrypt(
                        result['text'][i * max_length:(i + 1) * max_length],
                        key,
                        max_length)
                    out += irc_out_privmsg_build(result['to'], msg)

                return out
            else:
                msg = encrypt(result['text'], key, max_length)
                return irc_out_privmsg_build(result['to'], msg)

    return string


def buffer_closing_cb(data, signal, signal_data):
    server, channel = get_buffer_info(signal_data)

    if server is not None and channel is not None:
        dict_key = '{0}.{1}'.format(server, channel)
        if dict_key in channel_keys:
            del channel_keys[dict_key]
            weechat.bar_item_update(SCRIPT_NAME)
        return weechat.WEECHAT_RC_OK

    return weechat.WEECHAT_RC_ERROR


def statusbar_cb(data, item, window):
    if window:
        buf = weechat.window_get_pointer(window, 'buffer')
    else:
        buf = weechat.get_current_buffer()

    server, channel = get_buffer_info(buf)
    dict_key = '{0}.{1}'.format(server, channel)
    if dict_key in channel_keys:
        return "ENC"

    return ""


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", "UTF-8"):
    weechat.hook_command(SCRIPT_NAME,
                         "change weesodium options",
                         "[enable KEY] || "
                         "[disable]",
                         "",
                         "enable %-|| "
                         "disable",
                         "command_cb",
                         "")
    weechat.hook_modifier('irc_in_privmsg', 'in_privmsg_cb', '')
    weechat.hook_modifier('irc_out_privmsg', 'out_privmsg_cb', '')
    weechat.hook_signal('buffer_closing', 'buffer_closing_cb', '')

    statusbar = weechat.bar_item_new(SCRIPT_NAME, 'statusbar_cb', '')
    weechat.bar_item_update(SCRIPT_NAME)
