/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

class NativeCurve25519Provider implements Curve25519Provider {

    private static boolean libraryPresent = false;
    private static Throwable libraryFailedException = null;

    static {
        try {
            System.loadLibrary("curve25519");
            libraryPresent = true;
        } catch (UnsatisfiedLinkError | SecurityException outer) {
            try {
                loadFromJar();
                libraryPresent = true;
            } catch (UnsatisfiedLinkError | SecurityException inner) {
                libraryFailedException = inner.initCause(outer);
                libraryPresent = false;
            }
        }
    }

    private SecureRandomProvider secureRandomProvider = new JCESecureRandomProvider();

    NativeCurve25519Provider() throws NoSuchProviderException {
        if (!libraryPresent) throw new NoSuchProviderException(libraryFailedException);

        try {
            smokeCheck(31337);
        } catch (UnsatisfiedLinkError ule) {
            throw new NoSuchProviderException(ule);
        }
    }

    @Override
    public boolean isNative() {
        return true;
    }

    @Override
    public byte[] generatePrivateKey() {
        byte[] random = getRandom(PRIVATE_KEY_LEN);
        return generatePrivateKey(random);
    }

    @Override
    public byte[] getRandom(int length) {
        byte[] result = new byte[length];
        secureRandomProvider.nextBytes(result);

        return result;
    }

    @Override
    public void setRandomProvider(SecureRandomProvider provider) {
        this.secureRandomProvider = provider;
    }

    @Override
    public native byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic);

    @Override
    public native byte[] generatePublicKey(byte[] privateKey);

    @Override
    public native byte[] generatePrivateKey(byte[] random);

    @Override
    public native byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message);

    @Override
    public native boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature);

    @Override
    public native byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message);

    @Override
    public native byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
            throws VrfSignatureVerificationFailedException;

    private native boolean smokeCheck(int dummy);

    private static void loadFromJar() {
        String os = System.getProperty("os.name").toLowerCase();
        String path;
        if (os.contains("win")) {
            path = "/native/curve25519.dll";
        } else if (os.contains("mac")) {
            path = "/native/libcurve25519.dylib";
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            path = "/native/libcurve25519.so";
        } else {
            throw new UnsatisfiedLinkError("Can't find library for " + os);
        }

        try (InputStream in = NativeCurve25519Provider.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new UnsatisfiedLinkError("Can't find library for " + os);
            }
            Path fileOut = Files.createTempFile("curve25519", Long.toString(System.nanoTime()));
            Files.copy(in, fileOut, StandardCopyOption.REPLACE_EXISTING);
            System.load(fileOut.toFile().getAbsolutePath());
            fileOut.toFile().deleteOnExit();
        } catch (IOException e) {
            e.printStackTrace();
            throw new UnsatisfiedLinkError();
        }
    }
}
