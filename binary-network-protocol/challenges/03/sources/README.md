# Now everything with crypto!

# Create certificates

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 10000
```
Password for `cert.pem` is `binlog`.

## Build "standalone" Linux Binary

To obfuscate the code a little bit and make it not trivial to find the protocol structure, because the code is available for each participant, the code will be compiled using cython.

```
sudo pip3 install cython
```

```
python3 compile.py <file>
```

This will result in a linux executable which will be provided to the participant and can be found in the participant folder.
