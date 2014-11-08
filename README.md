# WeeSodium

WeeSodium is a WeeChat script for encrypting and authenticating messages in an
IRC channel with a shared key.

*DO NOT YET RELY ON THIS SCRIPT FOR STRONG SECURITY!* I hope to better explain
how WeeSodium works and the threat models it protects against soon.

## Usage
1. Drop weesodium.py into ~/.weechat/python/ or wherever you put your Python
   WeeChat scripts.
2. Run `/python load weesodium.py` in your WeeChat.
3. Add `[weesodium]` to your `weechat.bar.status.items` setting. If you are using the default WeeChat setting currently, you can do:
   ```
   /set weechat.bar.status.items "[time],[buffer_last_number],[buffer_plugin],buffer_number+:+buffer_name+(buffer_modes)+{buffer_nicklist_count}+buffer_zoom+buffer_filter,[weesodium],[lag],[hotlist],completion,scroll"
   ```
4. In the channel you want to use this with, do `/weesodium enable SECRETKEY`.
5. Use `/weesodium disable` to stop encryption in that channel.

## Persistent Key Storage
If you want to store keys persistently so that you do not have to enter them
each time you restart WeeChat, you can use WeeChat's secure storage:

1. `/sec set weesodium SECRETKEY`
2. `/set weesodium.keys.servername.#channelname ${sec.data.weesodium}`
