# encoding: utf-8

import base64
import libnacl.secret
import weechat

SCRIPT_NAME = 'weesodium'
SCRIPT_AUTHOR = 'mutantmonkey'
SCRIPT_VERSION = '20141027'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = "encrypt messages in a channel with libsodium"
#SCRIPT_COMMAND = 'weesodium'

def encrypt(msg, key, max_length=None):
    # math.ceil(384 / 3) * 4 = 512

    if max_length is not None:
        # FIXME: calculate how much space we actually need
        # these are probably not correct
        pad_length = max_length - libnacl.crypto_secretbox_NONCEBYTES \
                     - libnacl.crypto_secretbox_MACBYTES
        if len(msg) < pad_length:
            msg += b'\x00' * (pad_length - len(msg))

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


def in_privmsg(data, modifier, modifier_data, string):
    result = parse_privmsg(string)

    # TODO: decrypt message only if it is enabled for the channel and we have the key
    # FIXME: take a key from weechat settings for this channel
    key = b'\xf8\xe2\xdb\x94`\xdb7\xd1I08\xcf\xe0O \xf8\xb0\xcd\xc2\xd6\xf4\x0e\x9f\x8f&aps\x82\xd9\xf1\xd5'

    try:
        result['text'] = decrypt(result['text'], key)
    except:
        result['text'] = "Unable to decrypt: {}".format(result['text'])

    # FIXME: sanitize these bits
    return b":{from} PRIVMSG {to} :{text}".format(**result)


def out_privmsg(data, modifier, modifier_data, string):
    result = parse_privmsg(string)

    # TODO: encrypt message only if it is enabled for the channel and we have the key
    # FIXME: take a key from weechat settings for this channel
    # maybe use weesodium.[plugin].[server].[channel] or local buffer variable?
    key = b'\xf8\xe2\xdb\x94`\xdb7\xd1I08\xcf\xe0O \xf8\xb0\xcd\xc2\xd6\xf4\x0e\x9f\x8f&aps\x82\xd9\xf1\xd5'

    max_length = 270
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
            out += b"PRIVMSG {to} :{text}\n".format(to=result['to'], text=text)

        return out
    else:
        result['text'] = encrypt(result['text'], key, max_length)

        # FIXME: sanitize these bits
        return b"PRIVMSG {to} :{text}".format(**result)


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", "UTF-8"):
    # consider adding: notice, topic
    weechat.hook_modifier('irc_in_privmsg', 'in_privmsg', '')
    weechat.hook_modifier('irc_out_privmsg', 'out_privmsg', '')
