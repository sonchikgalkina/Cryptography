package org.example.cryptography.cryptography.Utils;

import java.security.SecureRandom;

public class IVGenerator {
    public static byte[] generate(int sizeInBytes) {
        byte[] IV = new byte[sizeInBytes];
        (new SecureRandom()).nextBytes(IV);

        return IV;
    }
}