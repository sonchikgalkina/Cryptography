package org.example.cryptography.cryptography.Interfaces;

public interface IPadding {
    byte[] applyPadding(byte[] data, int blockSize);

    byte[] removePadding(byte[] data);
}