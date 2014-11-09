# encoding: utf-8
#
# weesodium: encrypt messages in a channel with libsodium
# DO NOT YET RELY ON THIS SCRIPT FOR STRONG SECURITY!
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
import struct
import sys
import time
import weechat

SCRIPT_NAME = 'weesodium'
SCRIPT_AUTHOR = 'mutantmonkey'
SCRIPT_VERSION = '20141102'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = "encrypt messages in a channel with libsodium"

# messages outside of the current timestamp +/- this value will be rejected
TIMESTAMP_WINDOW_SECS = 300

IRC_SANITIZE_TABLE = dict((ord(char), None) for char in '\n\r\x00')
channel_data = {}


class WeeSodiumChannel(object):
    def __init__(self, key):
        self.key = hashlib.sha256(key).digest()
        self.counter = 0
        self.nonces = set()

    def get_nonce(self, nick):
        ts = int(time.time())
        nick_hash = hashlib.sha256(nick).digest()[:120]

        nonce = struct.pack('>QB15s', ts, self.counter % 255, nick_hash)
        self.nonces.add(nonce)
        self.counter += 1

        return nonce


class NonceError(Exception):
    pass


# helper functions {{{
def encrypt(channel, nick, msg, length=None):
    # pad message to length, if one is provided
    if length is not None and len(msg) < length:
        msg += b'\x00' * (length - len(msg))

    box = libnacl.secret.SecretBox(channel.key)
    ctxt = box.encrypt(msg, channel.get_nonce(nick))
    return base64.b64encode(ctxt)


def decrypt(channel, ctxt):
    ctxt = base64.b64decode(ctxt)
    nonce = ctxt[:libnacl.crypto_secretbox_NONCEBYTES]
    ctxt = ctxt[libnacl.crypto_secretbox_NONCEBYTES:]

    if len(nonce) != libnacl.crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")
    elif nonce in channel.nonces:
        raise NonceError(
            "Nonce reuse detected; this is either a bug or a replay attack in "
            "progress.")

    ts, counter, nick_hash = struct.unpack('>QB15s', nonce)
    if ts < time.time() - TIMESTAMP_WINDOW_SECS or \
            ts > time.time() + TIMESTAMP_WINDOW_SECS:
        raise NonceError(
            "Message timestamp was outside of the allowable window. Please "
            "check that your clock is set correctly.")

    box = libnacl.secret.SecretBox(channel.key)
    msg = box.decrypt(ctxt, nonce)
    msg = msg.rstrip(b'\x00')

    channel.nonces.add(nonce)
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
    if sys.version_info[0] >= 3:
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
# }}}


# callbacks {{{
def reload_config_cb(data, config_file):
    return weechat.config_reload(config_file)


def keys_read_option_cb(data, config_file, section, option, value):
    """Read option callback: load keys from config options"""

    weeopt = weechat.config_new_option(config_file, section, option, 'string',
                                       'key', '', 0, 0, '', value, 0,
                                       'keys_check_option_cb', '', '', '',
                                       '', '')
    if not weeopt:
        return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

    option_split = option.split('.')
    if len(option_split) == 2 and value.startswith('${sec.data.'):
        channel_key = weechat.string_eval_expression(value, {}, {}, {})
        channel_data[option] = WeeSodiumChannel(channel_key)

    return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def keys_create_option_cb(data, config_file, section, option, value):
    if not keys_check_option_cb('', option, value):
        weechat.prnt('',
                     "WeeSodium keys must be stored using WeeChat's secured "
                     "data storage. See /help secure for info on this.")
        return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

    option_split = option.split('.')
    if len(option_split) != 2:
        weechat.prnt('',
                     "Both a server and a channel are required to be entered "
                     "as the key for the config option. For example: "
                     "/set weesodium.keys.example.#weesodium "
                     "${sec.data.wskey}")
        return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

    weeopt = weechat.config_new_option(config_file, section, option, 'string',
                                       'key', '', 0, 0, '', value, 0,
                                       'keys_check_option_cb', '', '', '',
                                       '', '')
    if not weeopt:
        return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

    option_split = option.split('.')
    if len(option_split) == 2 and value.startswith('${sec.data.'):
        channel_key = weechat.string_eval_expression(value, {}, {}, {})
        channel_data[option] = WeeSodiumChannel(channel_key)

    return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def keys_check_option_cb(data, option, value):
    if value.startswith('${sec.data.'):
        return 1
    else:
        return 0


def command_cb(data, buf, args):
    try:
        args = shlex.split(args)
    except:
        return weechat.WEECHAT_RC_ERROR

    if len(args) == 2 and args[0] == b'enable':
        server, channel = get_buffer_info(buf)
        channel_data['{0}.{1}'.format(server, channel)] = WeeSodiumChannel(
            args[1])

        weechat.prnt(buf, "This conversation is now encrypted.")
        weechat.bar_item_update(SCRIPT_NAME)

        return weechat.WEECHAT_RC_OK
    elif len(args) == 1 and args[0] == b'disable':
        server, channel = get_buffer_info(buf)
        del channel_data['{0}.{1}'.format(server, channel)]

        weechat.prnt(buf, "This conversation is no longer encrypted.")
        weechat.bar_item_update(SCRIPT_NAME)

        return weechat.WEECHAT_RC_OK
    else:
        return weechat.WEECHAT_RC_ERROR


def in_privmsg_cb(data, modifier, modifier_data, string):
    result = parse_privmsg(string)
    if result['to_channel'] is not None:
        dict_key = '{0}.{1}'.format(modifier_data, result['to_channel'])
        if dict_key in channel_data:
            channel = channel_data[dict_key]

            try:
                result['text'] = decrypt(channel, result['text'])
            except NonceError as e:
                buf = weechat.info_get('irc_buffer', '{0},{1}'.format(
                    modifier_data, result['to_channel']))
                weechat.prnt(buf, "Error from {fromm}: {err}".format(
                    fromm=result['from'], err=e))
                return ""
            except:
                result['text'] = "Unable to decrypt: {}".format(result['text'])

            return irc_in_privmsg_build(result['from'], result['to'],
                                        result['text'])

    return string


def out_privmsg_cb(data, modifier, modifier_data, string):
    result = parse_privmsg(string)
    if result['to_channel'] is not None:
        dict_key = '{0}.{1}'.format(modifier_data, result['to_channel'])
        if dict_key in channel_data:
            channel = channel_data[dict_key]

            try:
                # this should result in messages that are 396 bytes long
                max_length = 297 - libnacl.crypto_secretbox_NONCEBYTES \
                    - libnacl.crypto_secretbox_MACBYTES
                if len(result['text']) > max_length:
                    # segment messages larger than max_length
                    out = ""
                    splits = 1 + (len(result['text']) // max_length)
                    for i in range(0, splits):
                        msg = encrypt(
                            channel,
                            result['from'],
                            result['text'][
                                i * max_length:(i + 1) * max_length],
                            max_length)
                        out += irc_out_privmsg_build(result['to'], msg)
                        out += "\r\n"

                    return out
                else:
                    msg = encrypt(channel, result['from'], result['text'],
                                  max_length)
                    return irc_out_privmsg_build(result['to'], msg)
            except Exception as e:
                buf = weechat.info_get('irc_buffer', '{0},{1}'.format(
                    modifier_data, result['to_channel']))
                weechat.prnt(buf, "Error while encrypting: {}".format(e))
                return ""

    return string


def buffer_closing_cb(data, signal, signal_data):
    server, channel = get_buffer_info(signal_data)

    if server is not None and channel is not None:
        dict_key = '{0}.{1}'.format(server, channel)
        if dict_key in channel_data:
            del channel_data[dict_key]
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
    if dict_key in channel_data:
        return "ENC"

    return ""
# }}}


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", "UTF-8"):
    # load config
    config_file = weechat.config_new(SCRIPT_NAME, 'reload_config_cb', '')
    weechat.config_new_section(config_file, 'keys', 1, 1,
                               'keys_read_option_cb', '',
                               '', '',
                               '', '',
                               'keys_create_option_cb', '',
                               '', '')
    weechat.config_read(config_file)

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
