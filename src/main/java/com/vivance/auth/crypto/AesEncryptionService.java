package com.vivance.auth.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES field encryption compatible with vivapi-user {@code AESConverter}
 * ({@code jasypt.aesencryptor.password}, SHA-1 derived 128-bit key).
 */
@Service
public class AesEncryptionService {

    private final String aesPassword;

    public AesEncryptionService(@Value("${jasypt.aesencryptor.password}") String aesPassword) {
        this.aesPassword = aesPassword;
    }

    public String encrypt(String plainText) {
        if (plainText == null) {
            return null;
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(deriveKey(aesPassword), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new IllegalStateException("Error encrypting value", e);
        }
    }

    public String decrypt(String cipherText) {
        if (cipherText == null) {
            return null;
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(deriveKey(aesPassword), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decoded = Base64.getDecoder().decode(cipherText);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Error decrypting value", e);
        }
    }

    private static byte[] deriveKey(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] key = sha.digest(password.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(key, 16);
    }
}
