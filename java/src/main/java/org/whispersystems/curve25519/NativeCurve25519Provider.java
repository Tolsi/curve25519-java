package org.whispersystems.curve25519;

import com.sun.jna.Library;
import com.sun.jna.Native;

public class NativeCurve25519Provider implements Curve25519Provider {
    private static Curve25519Library library;
    private static Throwable libraryFailedException;

    private SecureRandomProvider secureRandomProvider = new JCESecureRandomProvider();

    static {
        try {
            library = Native.load("curve25519", Curve25519Library.class);
            libraryFailedException = null;
        } catch (UnsatisfiedLinkError | SecurityException e) {
            library = null;
            libraryFailedException = e;
        }
    }

    NativeCurve25519Provider() {
        if (libraryFailedException != null) throw new NoSuchProviderException(libraryFailedException);

        try {
            library.smokeCheck(31337);
        } catch (UnsatisfiedLinkError ule) {
            throw new NoSuchProviderException(ule);
        }
    }

    @Override
    public boolean isNative() {
        return true;
    }

    @Override
    public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
        byte[] sharedKey = new byte[32];
        library.calculateAgreement(sharedKey, ourPrivate, theirPublic);
        return sharedKey;
    }

    @Override
    public byte[] generatePublicKey(byte[] privateKey) {
        byte[] publicKey = new byte[32];
        library.generatePublicKey(publicKey, privateKey);
        return publicKey;
    }

    @Override
    public byte[] generatePrivateKey() {
        byte[] privateKey = getRandom(PRIVATE_KEY_LEN);
        library.generatePrivateKey(privateKey);
        return privateKey;
    }

    @Override
    public byte[] generatePrivateKey(byte[] random) {
        library.generatePrivateKey(random);
        return random;
    }

    @Override
    public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message) {
        byte[] signature = new byte[64];
        int result = library.calculateSignature(signature, random, privateKey, message, message.length);
        if (result != 0) {
            System.out.println("Failed");
            throw new AssertionError("Signature failed!");
        }
        return signature;
    }

    @Override
    public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        return library.verifySignature(publicKey, message, message.length, signature) == 0;
    }

    @Override
    public byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message) {
        byte[] signature = new byte[96];
        int result = library.calculateVrfSignature(signature, random, privateKey, message, message.length);
        if (result != 0) throw new AssertionError("Signature failed!");
        return signature;
    }

    @Override
    public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature) throws VrfSignatureVerificationFailedException {
        byte[] vrf = new byte[32];
        int result = library.verifyVrfSignature(vrf, publicKey, message, message.length, signature);
        if (result != 0) throw new VrfSignatureVerificationFailedException("Invalid signature");
        return vrf;
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

    public interface Curve25519Library extends Library {
        void generatePrivateKey(byte[] random);
        void generatePublicKey(byte[] publicKey, byte[] privateKey);
        void calculateAgreement(byte[] sharedKey, byte[] privateKey, byte[] publicKey);
        int calculateSignature(byte[] signature, byte[] random, byte[] privateKey, byte[] message, long messageLength);
        int verifySignature(byte[] publicKey, byte[] message, long messageLength, byte[] signature);
        int calculateVrfSignature(byte[] signature, byte[] random, byte[] privateKey, byte[] message, long messageLength);
        int verifyVrfSignature(byte[] vrf, byte[] publicKey, byte[] message, long messageLength, byte[] signature);
        int smokeCheck(int dummy);
    }
}
