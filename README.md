## What is it?
A <ins>minimal CLI program to decrypt your dailytxt files</ins>, even if the server is shut down or not working any longer.

It's written in rust and needs the exact same filestructure as created by the dailytxt server.  
So even when you just use your standard server-backup-method (e.g. rsync), you can later use this program on your desktop-PC to decrypt your files.

It's <ins>not</ins> a tool to *break* the encryption! You still need to know your password (and your username, but you can also find your username in the users.json file).

You can choose to either decrypt all logs ever written at once or just a specific month.

## Download and start
Download it from [the release-area](https://github.com/PhiTux/dailytxt-decrypt-cli/releases) here on github (or compile it by yourself).

Find all the necessary commands in the CLI by running `./dailytxt-decrypt-cli --help`.
