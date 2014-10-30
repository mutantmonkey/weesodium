# encoding: utf-8

import base64
import hashlib
import libnacl.secret
import shlex
import weechat

SCRIPT_NAME = 'weesodium'
SCRIPT_AUTHOR = 'mutantmonkey'
SCRIPT_VERSION = '20141029'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = "encrypt messages in a channel with libsodium"

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
    # partially based upon weechat-otr, licensed under the GPL3
    # Copyright (c) 2012-2014 Matthew M. Boedicker <matthewm@boedicker.org>
    # Nils Görs <weechatter@arcor.de>
    # Daniel "koolfy" Faucon <koolfy@koolfy.be>
    # Felix Eckhofer <felix@tribut.de>

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
                return string

            # FIXME: sanitize these bits
            return b":{from} PRIVMSG {to} :{text}".format(**result)

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
                out = b""
                splits = 1 + (len(result['text']) // max_length)
                for i in range(0, splits):
                    text = encrypt(
                        result['text'][i * max_length:(i + 1) * max_length],
                        key,
                        max_length)

                    # FIXME: sanitize these bits
                    out += b"PRIVMSG {to} :{text}\n".format(to=result['to'],
                                                            text=text)

                return out
            else:
                result['text'] = encrypt(result['text'], key, max_length)

                # FIXME: sanitize these bits
                return b"PRIVMSG {to} :{text}".format(**result)

    return string


def command_cb(data, buf, args):
    try:
        args = shlex.split(args)
    except:
        return weechat.WEECHAT_RC_ERROR

    if len(args) == 2 and args[0] == b'enable':
        server, channel = get_buffer_info(buf)
        key = hashlib.sha256(args[1]).digest()

        # requires python 2.7.8 or 3.4 :(
        #key = hashlib.pbkdf_hmac('sha256', args[1], libnacl.randombytes(16),
        #                         100000)

        channel_keys['{0}.{1}'.format(server, channel)] = key
        weechat.bar_item_update(SCRIPT_NAME)

        return weechat.WEECHAT_RC_OK
    elif len(args) == 1 and args[0] == b'disable':
        server, channel = get_buffer_info(buf)
        del channel_keys['{0}.{1}'.format(server, channel)]
        weechat.bar_item_update(SCRIPT_NAME)

        return weechat.WEECHAT_RC_OK
    else:
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


def get_buffer_info(buf):
    server = weechat.buffer_get_string(buf, b'localvar_server').decode('utf-8')
    channel = weechat.buffer_get_string(buf, b'localvar_channel').decode(
        'utf-8')
    return server, channel


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", "UTF-8"):
    # consider adding: notice, topic
    weechat.hook_modifier('irc_in_privmsg', 'in_privmsg_cb', '')
    weechat.hook_modifier('irc_out_privmsg', 'out_privmsg_cb', '')
    weechat.hook_command(SCRIPT_NAME,
                         "change weesodium options",
                         "[enable KEY] || "
                         "[disable]",
                         "",
                         "enable %-|| "
                         "disable",
                         "command_cb",
                         "")

    statusbar = weechat.bar_item_new(SCRIPT_NAME, 'statusbar_cb', '')
    weechat.bar_item_update(SCRIPT_NAME)
