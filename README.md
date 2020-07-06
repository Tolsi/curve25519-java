# curve25519-java

A Java Curve25519 implementation that is backed by native code when available, and
pure Java when a native library is not available.

## Building

### JVM

Just use Gradle, for example `gradle compileJava` or `gradle jar` to build jar.

### Native

Call it from the root of project:

```
mkdir native/build
cd native/build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
```

### Benchmark tests

To run it call ```gradle jmh```

## Using

## Obtaining an instance

The caller needs to specify a `provider` when obtaining a Curve25519 instance.  There are
four built in providers:

1. `Curve25519.NATIVE` -- This is a JNA backed provider.
1. `Curve25519.JAVA` -- This is a pure Java 7 backed provider.
1. `Curve25519.J2ME` -- This is a J2ME compatible provider.
1. `Curve25519.BEST` -- This is a provider that attempts to use `NATIVE`,
   but falls back to `JAVA` if the former is unavailable.

The caller specifies a provider during instance creation:

```
Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
```

Since J2ME doesn't have built-in `SecureRandom` support, J2ME users need to supply their
own source of `SecureRandom` by implementing the `SecureRandomProvider` interface and
passing it in:

```
Curve25519 cipher = Curve25519.getInstance(Curve25519.J2ME, new MySecureRandomProvider());
```

### Generating a Curve25519 keypair:

```
Curve25519KeyPair keyPair = Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
```

### Calculating a shared secret:

```
Curve25519 cipher       = Curve25519.getInstance(Curve25519.BEST);
byte[]     sharedSecret = cipher.calculateAgreement(publicKey, privateKey);
```

### Calculating a signature:

```
Curve25519 cipher    = Curve25519.getInstance(Curve25519.BEST);
byte[]     signature = cipher.calculateSignature(secureRandom, privateKey, message);
```

### Verifying a signature:

```
Curve25519 cipher         = Curve25519.getInstance(Curve25519.BEST);
boolean    validSignature = cipher.verifySignature(publicKey, message, signature);
```

## License

Copyright 2015 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

Updated by Waves Platform in 2019-2020
