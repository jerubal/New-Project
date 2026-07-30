package org.insa.pkiissuingca.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Converter
@Component
public class PrivateKeyEncryptionConverter implements AttributeConverter<String, String> {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH_BYTES = 12;

    // Populated via ${PKI_DB_ENCRYPTION_KEY} — no default is provided.
    // The application will refuse to start if this env var is absent.
    private static String secretKeyBase64;

    @Value("${pki.security.db-encryption-key}")
    public void setSecretKeyBase64(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalStateException(
                "[SECURITY] pki.security.db-encryption-key must be set via the PKI_DB_ENCRYPTION_KEY " +
                "environment variable. Generate one with: openssl rand -base64 32");
        }
        String trimmed = key.trim();
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(trimmed);
        } catch (IllegalArgumentException e) {
            decoded = trimmed.getBytes(StandardCharsets.UTF_8);
        }
        if (decoded.length != 32) {
            throw new IllegalStateException(
                "[SECURITY] Decoded PKI_DB_ENCRYPTION_KEY must be exactly 32 bytes (256 bits) long. " +
                "Actual length: " + decoded.length + " bytes.");
        }
        PrivateKeyEncryptionConverter.secretKeyBase64 = trimmed;
    }

    private static SecretKey getSecretKey() {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(secretKeyBase64);
        } catch (IllegalArgumentException e) {
            keyBytes = secretKeyBase64.getBytes(StandardCharsets.UTF_8);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), spec);

            byte[] cipherText = cipher.doFinal(attribute.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);

            return "ENC:" + Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            throw new IllegalStateException("Error encrypting private key at rest", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        // If data was not encrypted yet (legacy format), return as-is
        if (!dbData.startsWith("ENC:")) {
            return dbData;
        }

        try {
            String base64Data = dbData.substring(4);
            byte[] cipherTextWithIv = Base64.getDecoder().decode(base64Data);

            ByteBuffer byteBuffer = ByteBuffer.wrap(cipherTextWithIv);
            byte[] iv = new byte[IV_LENGTH_BYTES];
            byteBuffer.get(iv);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec);

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Error decrypting private key from DB", e);
        }
    }
}
