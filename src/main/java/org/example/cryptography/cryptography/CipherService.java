package org.example.cryptography.cryptography;

import lombok.extern.slf4j.Slf4j;
import org.example.cryptography.cryptography.CipherMode.ACipherMode;
import org.example.cryptography.cryptography.CipherMode.CipherMode;
import org.example.cryptography.cryptography.Interfaces.IEncryptor;
import org.example.cryptography.cryptography.Interfaces.IPadding;
import org.example.cryptography.cryptography.Padding.PaddingMode;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Slf4j
public class CipherService {
    private final ExecutorService executorService;
    private final int blockLength;
    private final ACipherMode cipherMode;
    private final IPadding padding;

    public CipherService(
            byte[] key,
            IEncryptor encryptor,
            CipherMode.Mode cypherMode,
            PaddingMode.Mode paddingMode,
            byte[] IV) {
        blockLength = encryptor.getBlockLength();
        encryptor.setKeys(key);

        executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() - 1);
        padding = PaddingMode.getInstance(paddingMode);
        cipherMode = CipherMode.getInstance(cypherMode, encryptor, IV, executorService);

        log.info("CryptoContext build successfully");
    }

    public CompletableFuture<byte[]> encrypt(byte[] text) {
        return CompletableFuture.supplyAsync(() -> cipherMode.encrypt(padding.applyPadding(text, blockLength)));
    }

    public CompletableFuture<byte[]> decrypt(byte[] cipherText) {
        return CompletableFuture.supplyAsync(() -> padding.removePadding(cipherMode.decrypt(cipherText)));
    }

    public void close() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(2, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
}
