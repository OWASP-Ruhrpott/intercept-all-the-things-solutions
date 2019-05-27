# Binary Login

This directory includes a made up protocol for a some binary communication.

## Protocol

The protocol consists of following parts:

### Get User ID
```
42|username
```

### Login
```
01|length|02|length_payload|03|user_id|password|04|MD5(01|length|02|length_payload|03|user_id|password)|ffff
```

#### Usernames, User IDs and Passwords
```
0000 Admin                  admin
0001 Standard user (Bob)    bobisthebest
0002 Standard user (Alice)  aliceisthebest
0003 - ffff no user
```

## Build "standalone" Linux Binary

To obfuscate the code a little bit and make it not trivial to find the protocol structure, because the code is available for each participant, the code will be compiled using cython.

```
sudo pip3 install cython
```

```
python3 compile.py <file>
```

This will result in a linux executable which will be provided to the participant and can be found in the participant folder.
