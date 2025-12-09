# private information tracker

PIT acts as a vault obfuscation tool allowing you to encrypt folders and files into compressed data object files which
can only be accessed again using the master password.

I originally wrote this as a more secure way to store my passwords locally, so PIT comes with some more specialized
commands on credentials management.

Please note that this tool is very specific to my own use-cases and may lack some general UX for other people.

![CLI](/.github/media/cli.png)

Set up your vault using

``
java -jar pit.jar init example // vault name
``

![Session](/.github/media/session.png)

Add your first identity to it:

``
generate google
``

This will return a random generated password to be then used on the website.

To quit:

``
exit
``

----

Get the password again by:

``
java -jar pit.jar session example
``

``
copy google
``

``
exit
``

### Downloads

You can download the latest jar file
from [my build server](https://build.florianmichael.de/job/pit), [GitHub Actions](https://github.com/FlorianMichael/pit/actions)
or use the [releases tab](https://github.com/FlorianMichael/pit/releases).

## Contact

If you encounter any issues, please report them on the
[issue tracker](https://github.com/FlorianMichael/pit/issues).  
If you just want to talk or need help with pit feel free to join my
[Discord](http://florianmichael.de/discord).
