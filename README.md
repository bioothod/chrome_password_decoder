# chrome_password_decoder
Linux chrome/chromium password decoder

Supported both v10 (static key encryption) and v11 (a master
key stored in the OS keyring manager is used for password encryption)
protocols. For v11 protocol all available to `libsecret` keyring
managers and all stored master keys will be used, only passwords
decoded into ascii string will be shown.

Requires `libsecret` to access keyrings and `pycryptodome` for crypto
ops and a few standard packages.
