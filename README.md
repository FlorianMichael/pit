# private information tracker

## Terminology

Originally meant to be a password management tool, PIT acts as a vault obfuscation tool allowing you to encrypt folders and files
into compressed data object files which can only be accessed again using the master password.

![CLI](/.github/media/cli.png)

Set up your vault using 

``
java -jar pit.jar --init passwords
``

Add your first identity to it:

``
java -jar pit.jar --generate google
``

This will return a random generated password to be then used on the website.

View again by:

``
java -jar pit.jar --view passwords google
``

## Contact
If you encounter any issues, please report them on the
[issue tracker](https://github.com/FlorianMichael/pit/issues).  
If you just want to talk or need help with pit feel free to join my
[Discord](https://discord.gg/BwWhCHUKDf).
