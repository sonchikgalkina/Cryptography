package org.example.cryptography.cryptography.Algorithms.LOKI97;

import org.example.cryptography.cryptography.Interfaces.IEncryptor;


public class LOKI97 implements IEncryptor {
    public static final int KEY_LENGTH_LOKI97_16 = 16;
    public static final int KEY_LENGTH_LOKI97_24 = 24;
    public static final int KEY_LENGTH_LOKI97_32 = 32;
    public static final int BLOCK_LENGTH_LOKI97 = 16;

    private final int roundCount = 16;
    private FeistelCipherLOKI97 cipherEncryption;
    private FeistelCipherLOKI97 cipherDecryption;

    public LOKI97(byte[] key) {
        int lenKey = key.length;
        if (!(lenKey == 16 || lenKey == 24 || lenKey == 32)) {
            throw new IllegalArgumentException("LOKI97: Param key must be of size 16, 24 or 32");
        }

        EncryptionConversionFeistelFunctionLOKI97 encryptionConversionFeistelFunctionLOKI97 = new EncryptionConversionFeistelFunctionLOKI97();
        RoundKeyGenerationLOKI97 roundKeyGenerationLOKI97 = new RoundKeyGenerationLOKI97(encryptionConversionFeistelFunctionLOKI97);
        this.cipherEncryption = new FeistelCipherLOKI97(roundKeyGenerationLOKI97, encryptionConversionFeistelFunctionLOKI97, key);
        this.cipherDecryption = new FeistelCipherLOKI97(roundKeyGenerationLOKI97, encryptionConversionFeistelFunctionLOKI97, key);
    }


    @Override
    public byte[] encode(byte[] data) {
        if (data == null || data.length != BLOCK_LENGTH_LOKI97) {
            throw new IllegalArgumentException("Input block must be 16 bytes");
        }
        return cipherEncryption.methodForConstructingBlockCiphersEncryption(data, roundCount);
    }

    @Override
    public byte[] decode(byte[] data) {
        if (data == null || data.length != BLOCK_LENGTH_LOKI97) {
            throw new IllegalArgumentException("Input block must be 16 bytes");
        }
        return cipherDecryption.methodForConstructingBlockCiphersDecryption(data, roundCount);
    }

    @Override
    public void setKeys(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }
        int lenKey = key.length;
        if (!(lenKey == KEY_LENGTH_LOKI97_16 || lenKey == KEY_LENGTH_LOKI97_24 || lenKey == KEY_LENGTH_LOKI97_32)) {
            throw new IllegalArgumentException("Key length must be 16, 24 or 32 bytes");
        }

        EncryptionConversionFeistelFunctionLOKI97 encConv = new EncryptionConversionFeistelFunctionLOKI97();
        RoundKeyGenerationLOKI97 keyGen = new RoundKeyGenerationLOKI97(encConv);

        this.cipherEncryption = new FeistelCipherLOKI97(keyGen, encConv, key);
        this.cipherDecryption = new FeistelCipherLOKI97(keyGen, encConv, key);
    }

    @Override
    public int getBlockLength() {
        return BLOCK_LENGTH_LOKI97;
    }
}


