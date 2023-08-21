# Node - Import-only Utility

This release is to gather as many folks who participated in the first phase of
the ceremony together to be ready for the network launch. To be ready, run
with:

    go run ./... -import-priv-key `cat /path/to/voucher.hex`

You will get output like the following:

    Creating config directory ./.config/
    Generating default config...
    Generating random host key...
    Generating keystore key...
    Saving config...
    Peer ID: <Peer ID>
    Import completed, you are ready for the launch.

Post the Peer ID in the Farcaster thread.