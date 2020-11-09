package org.whispersystems.curve25519;

import javax.xml.bind.DatatypeConverter;

public class HexBin {
    public static byte[] decode(String hexString) {
        return DatatypeConverter.parseHexBinary(hexString);
    }
}
