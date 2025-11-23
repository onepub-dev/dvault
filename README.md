# Overview

DVault is designed to make protecting (encrypting) files and directories simple and secure.
When protecting a file or directory DVault uses the terms 'lock' and 'unlock' to indicate the process of protecting (locking) a file or directroy and opening (unlocking) a file or directory.

When you lock a file or directory with DVault it creates a single self contained 'lockbox' file.

DVault uses a passphrase to protected a lockbox, however you only need your passphrase when opening a lockbox.

DVault works as a simple interactive command line tool but is also designed to be called by other scripts.

DVault supports Linux, Mac OSX and Windows. 
For those interested; the gory technical details about RSA and AES are covered below.


## Locking a file
When you lock a file with DVault the original file or directory is (optionally) deleted and replaced with a new .lbox file.

e.g. important.txt becomes important.txt.lbox.

When you unlock a lockbox, the lockbox is deleted and your original file is restored.

e.g. important.txt.lbox becomes important.txt

# Initialise DVault
To install DVault run:
```
dart pub global activate dvault
```

After installing DVault you need to run a one time initialisation process:

```
dvault init
  Enter passphrase: ******
  Confirm passphrase: ***** 
  Generating keys, this make take a couple of minutes.
  Generating: ......
  Keys saved to ~/.dvault

  Be sure to backup the ~/.dvault file as it is critical to unlocking your lockboxes.
```

## Lock the file
To lock a file:
```
dvault lock important.txt
  Stored and locked in important.txt.lbox.
```

## Unlock the file
To unlock an existing lockbox you need the passphrase used when initialising dvault.

```
dvault unlock important.txt.lbox
  Passphrase: ****** 
  Unlocked to important.txt
```

As a .lbox file contains the original keys, the lockbox can be copied to any machine and provided you know the passphrase you can always unlock the file.

# Send a lockbox to a friend
If you want to send an lbox to a friend, you can create a lockbox using a single use passphrase which you can share with a friend.

```
dvault share important.txt
   Looks like you are going to share a lockbox with a friend.
   When prompted enter a passphrase that you can give to your friend.
   **** DO NOT USE YOUR NORMAL DVAULT PASSPHRASE ****
   Enter passphrase: *****
   Confirm passphrase: *****
   Stored and locked in important.txt.lbox
   
   Call your friend and give them the passphase or send it to them via
   some other secure means. 
   **** DO NOT EMAIL OR TWEET THE PASSPHRASE! ****
   Email 'imporantant.txt.lbox to your friend'
   
   You may also want to send them the following instruction.
   
   Please find the attached .lbox file which contains the documents discussed.
   To unlock the lockbox you will need to download and install DVault from
   https://github.com/onepub-dev/dvault/wiki/Shared-Vault
   The above link also contains instructions on how to unlock the lockbox.
   I will ring with the required passphrase shortly.

```   


# Technical details

## Key management.
When you run dvault init a public/private key pair is created and stored into the ~/.dvault file (or suitable per user OS sepecific location). The dvault file is configured with appropriate permissions to prevent unauthorised access.

When you create a lockbox, a per lockbox session key is created and stored in the lockbox after being encrypted with your 
public key (from the .dvault file).
When you add files to the lockbox the session key is used to encrypt those files.

To unlock the lockbox, the session key is decrypted using your private key (from the .dvault file).

If you loose the .dvault file then you will loose access to ALL your lockboxes, so it is critical to backup your .dvault file.





