About
=====

MobilePasser is a virtual environment and set of scripts to quickly generate a
large number of mobile pass passwords. These can be helpful if you're trying to
automate an action which requires a mobile pass token for authentication. It
also allows you to sync the password list between multiple devices so you're
not tied to whatever device is running the mobile pass software.

Warning
-------

Saving a list of passwords to a file will significantly reduce the security of
your system and is not advised. I mainly put this together as your network
security was slightly overzealous in its use of mobile pass and was getting in
the way for no good reason.

It's probably a good idea to keep the list in an encrypted file system that you
can mount when you need access to it and keep unmounted the rest of the time.
As long as you choose a secure password this is probably more secure than the
four digit pin normally required to retrieve a OTP.

Instructions
============

First Boot
----------

The standard ubuntu images don't ship with a gui. XFCE and gdm will be
installed by puppet on the first boot, after which you'll need to restart the
vm.

Scrapping Passwords
-------------------

1. Open a document to store the passwords in. (Run application -> mobilepad)
2. Open the mobilepass application.
3. Choose your token and enter your pin.
4. Run /vagrant/files/record.sh
5. Click the generate button, double click the centre of the code, copy the
   text, alt + tab to the editor, paste the password and a new line, alt+tab
   back.
6. Stop the recording.
7. Run /vargrant/files/scrape.sh to start collecting passwords.

Using Passwords
---------------

You probably want to add the following to your shell rc file:

```
alias mobilepass=/path/to/project/get-mobilepass.sh
```

Then you can get the next valid mobile pass at any point by calling
"mobilepass".

ToDo
====

The copying and pasting seems to work better when we disable clipboard sharing
with the host. We should probably do this anyway to avoid it messing with
anything we might be doing at the same time. Add a line to the vagrant config
to set this option on start up.

The mobilepass application doesn't run well from a mounted directory so we
should copy it to the desktop during startup.

Alternative Approaches
======================
One idea might be to try and reimplement the generation algorithm so that we
can hardcode the password. Unfortuantely MobilePass's implementation of
HOTP HMAC-SHA256 is non-standard and there's no easy way to determine what
they've changed without decompiling one of their clients (note to those who
want to attempt this: the source code is also obfuscated.)

A second option might be to use the MobilePass SDK to generate the passcodes
[1]. Unfortunately, the SDK requires an "import token data file" as created by
MobilePass Factory and finding a copy of that software appears difficult.

Links
=====
[1] http://www.safenet-inc.com/support/safeword/premier-access-authentication-sdk.aspx
