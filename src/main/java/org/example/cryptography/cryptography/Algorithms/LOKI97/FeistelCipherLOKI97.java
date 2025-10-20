package org.example.cryptography.cryptography.Algorithms.LOKI97;

import org.example.cryptography.cryptography.Interfaces.EncryptionConversion;
import org.example.cryptography.cryptography.Interfaces.RoundKeyGeneration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FeistelCipherLOKI97 {
    private static final Logger log = LoggerFactory.getLogger(FeistelCipherLOKI97.class);
    private static byte[][] roundKeys;
    private final EncryptionConversion encryptionConversion;

    public FeistelCipherLOKI97(RoundKeyGeneration keyGen, EncryptionConversion conversion, byte[] key) {
        if (keyGen == null) throw new IllegalArgumentException("keyGen is null");
        if (conversion == null) throw new IllegalArgumentException("conversion is null");
        if (key == null) throw new IllegalArgumentException("key is null");

        this.encryptionConversion = conversion;
        roundKeys = keyGen.generateRoundKeys(key);
    }

    public byte[] methodForConstructingBlockCiphersEncryption(byte[] input, int roundCount) {
        if (roundCount * 3 != roundKeys.length) {
            throw new IllegalArgumentException("roundCount must be equal to roundKeys.length / 3");
        }
        if (input.length != 16) {
            throw new IllegalArgumentException("Input length must be 16 bytes");
        }

        int halfLen = input.length / 2;
        byte[] left = new byte[halfLen];
        byte[] right = new byte[halfLen];
        System.arraycopy(input, 0, left, 0, halfLen);
        System.arraycopy(input, halfLen, right, 0, halfLen);

        for (int i = 1; i <= roundCount; i++) {
            int idx = 3 * i - 1;
            byte[] tmp = Operations.xor(
                    left,
                    encryptionConversion.encrypt(
                            Operations.additionByteArraysLength8(
                                    right,
                                    roundKeys[idx - 2]),
                            roundKeys[idx - 1]
                    )
            );

            left = Operations.additionByteArraysLength8(
                    Operations.additionByteArraysLength8(right, roundKeys[idx - 2]),
                    roundKeys[idx]
            );
            right = tmp;
        }

        return Operations.mergeByteArrays(right, left);
    }

    public byte[] methodForConstructingBlockCiphersDecryption(byte[] input, int roundCount) {
        if (roundCount * 3 != roundKeys.length) {
            throw new IllegalArgumentException("roundCount must be equal to roundKeys.length / 3");
        }
        if (input.length != 16) {
            throw new IllegalArgumentException("Input length must be 16 bytes");
        }

        int halfLen = input.length / 2;
        byte[] right = new byte[halfLen];
        byte[] left = new byte[halfLen];
        System.arraycopy(input, 0, right, 0, halfLen);
        System.arraycopy(input, halfLen, left, 0, halfLen);

        for (int i = roundCount; i >= 1; i--) {
            int idx = 3 * i - 1;
            byte[] tmp = Operations.xor(
                    right,
                    encryptionConversion.encrypt(
                            Operations.subtractionByteArraysLength8(left, roundKeys[idx]),
                            roundKeys[idx - 1]
                    )
            );

            right = Operations.subtractionByteArraysLength8(
                    Operations.subtractionByteArraysLength8(left, roundKeys[idx]),
                    roundKeys[idx - 2]
            );
            left = tmp;
        }

        return Operations.mergeByteArrays(left, right);
    }
}

