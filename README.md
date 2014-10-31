# WeeSodium

WeeSodium is a WeeChat script for encrypting and authenticating messages in an
IRC channel with a shared key.

*DO NOT YET RELY ON THIS SCRIPT FOR STRONG SECURITY!* I hope to better explain
how WeeSodium works and the threat models it protects against soon.

## Usage
1. Drop weesodium.py into ~/.weechat/python/ or wherever you put your Python
   WeeChat scripts.
2. Run `/python load weesodium.py` in your WeeChat.
3. In the channel you want to use this with, do `/weesodium enable SECRETKEY`.
4. Use `/weesodium disable` to stop encryption in that channel.
