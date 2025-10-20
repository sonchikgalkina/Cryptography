package org.example.cryptography.cryptography.Algorithms.MARS;

import org.example.cryptography.cryptography.Interfaces.IEncryptor;

public class MARS implements IEncryptor {
    private final IEncryptor feistelNetwork;

    public MARS() {
        this.feistelNetwork = new MARSFeistelNetwork(new MARSKeyExpand(), new MARSRoundFunction());
    }

    @Override
    public byte[] encode(byte[] in) {
        return feistelNetwork.encode(in);
    }

    @Override
    public byte[] decode(byte[] in) {
        return feistelNetwork.decode(in);
    }

    @Override
    public void setKeys(byte[] key) {
        feistelNetwork.setKeys(key);
    }

    @Override
    public int getBlockLength() {
        return feistelNetwork.getBlockLength();
    }
}
