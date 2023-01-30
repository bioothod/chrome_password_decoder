# chrome_password_decoder
Linux chrome/chromium password decoder

So far only v10 protocol is supported - it uses static salt/password and pbkdf2 encrption key generation.
V11 protocol uses master key obtained from the system (whether it is linux or not) - from gnome-keyring, libsecure, kwallet and so on
