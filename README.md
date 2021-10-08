# isaac-crypto
A simple file command line utility for file encryption using the ISAAC cryptographic pseudo-random number generator.
The implementation of the random number generator is not mine, but the method of seeding the state from a passphrase and the feedforward cipher element are both mine.
# compiling
> $ gcc -o ic ic.c
# running
```
 $ ic <commandflags> passphrase  input-file output-file
  e encrypt the input-file, write result to output-file
  d decrypt the input-file, write result to output-file
```
