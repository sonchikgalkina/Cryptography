package org.example.cryptography.cryptography.Algorithms.LOKI97;

import org.example.cryptography.cryptography.Interfaces.RoundKeyGeneration;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class RoundKeyGenerationLOKI97 implements RoundKeyGeneration {
    private final EncryptionConversionFeistelFunctionLOKI97 encryptionConversion;
    private static final int ROUND_COUNT = 16;
    private static final long DELTA = 0x9E3779B97F4A7C15L;

    public RoundKeyGenerationLOKI97(EncryptionConversionFeistelFunctionLOKI97 encryptionConversion) {
        this.encryptionConversion = encryptionConversion;
    }

    private byte[] g(byte[] K1, byte[] K3, byte[] K2, int i) {
        long deltaMult = DELTA * i;
        return encryptionConversion.encrypt(
                Operations.additionByteArraysLength8(
                        K1,
                        Operations.additionByteArrayLength8AndLong(K3, deltaMult)),
                K2);
    }

    @Override
    public byte[][] generateRoundKeys(byte[] key) {
        int len = key.length;
        byte[] K1, K2, K3, K4;

        if (len == 16) {
            K4 = Arrays.copyOfRange(key, 0, 8);
            K3 = Arrays.copyOfRange(key, 8, 16);
            K2 = encryptionConversion.encrypt(K3, K4);
            K1 = encryptionConversion.encrypt(K4, K3);
        } else if (len == 24) {
            K4 = Arrays.copyOfRange(key, 0, 8);
            K3 = Arrays.copyOfRange(key, 8, 16);
            K2 = Arrays.copyOfRange(key, 16, 24);
            K1 = encryptionConversion.encrypt(K4, K3);
        } else if (len == 32) {
            K4 = Arrays.copyOfRange(key, 0, 8);
            K3 = Arrays.copyOfRange(key, 8, 16);
            K2 = Arrays.copyOfRange(key, 16, 24);
            K1 = Arrays.copyOfRange(key, 24, 32);
        } else {
            throw new IllegalArgumentException("Key length must be 16, 24 or 32");
        }

        byte[][] roundKeys = new byte[48][8];
        for (int i = 1; i <= 48; i++) {
            roundKeys[i - 1] = Operations.xor(K4, g(K1, K3, K2, i));
            K4 = K3;
            K3 = K2;
            K2 = K1;
            K1 = roundKeys[i - 1].clone();
        }

        return roundKeys;
    }
}

