package org.example.cryptography.cryptography.Interfaces;

public interface IRoundFunction {
    byte[] eFunction(byte[] block, byte[] roundKey);
}
