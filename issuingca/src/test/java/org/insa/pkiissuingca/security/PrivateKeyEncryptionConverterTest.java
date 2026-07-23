package org.insa.pkiissuingca.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PrivateKeyEncryptionConverterTest {

    private final PrivateKeyEncryptionConverter converter = new PrivateKeyEncryptionConverter();

    @Test
    public void testEncryptionAndDecryption() {
        String originalPem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3...\n-----END PRIVATE KEY-----";

        String dbValue = converter.convertToDatabaseColumn(originalPem);

        assertNotNull(dbValue);
        assertNotEquals(originalPem, dbValue);
        assertTrue(dbValue.startsWith("ENC:"));

        String decryptedPem = converter.convertToEntityAttribute(dbValue);
        assertEquals(originalPem, decryptedPem);
    }

    @Test
    public void testNullAndEmpty() {
        assertNull(converter.convertToDatabaseColumn(null));
        assertNull(converter.convertToEntityAttribute(null));
        assertEquals("", converter.convertToDatabaseColumn(""));
        assertEquals("", converter.convertToEntityAttribute(""));
    }

    @Test
    public void testUnencryptedLegacyFallback() {
        String legacyPem = "-----BEGIN PRIVATE KEY-----\nUNENCRYPTED_LEGACY_PEM\n-----END PRIVATE KEY-----";
        assertEquals(legacyPem, converter.convertToEntityAttribute(legacyPem));
    }
}
