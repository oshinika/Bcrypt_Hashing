/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 */
package org.wso2.carbon.identity.hash.provider.bcrypt;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

/**
 * Test class for BcryptHashProvider.
 */
public class BcryptHashProviderTest {

    private BcryptHashProvider bcryptHashProvider;
    private String validSalt;

    @BeforeMethod
    public void setUp() {
        bcryptHashProvider = new BcryptHashProvider();
        bcryptHashProvider.init();

        // Create a valid 16-byte salt for testing
        byte[] saltBytes = new byte[Constants.BCRYPT_SALT_LENGTH];
        for (int i = 0; i < saltBytes.length; i++) {
            saltBytes[i] = (byte) i;
        }
        validSalt = Base64.getEncoder().encodeToString(saltBytes);
    }

    @Test
    public void testInitWithDefaultValues() {
        bcryptHashProvider.init();
        assertEquals(bcryptHashProvider.getAlgorithm(), "BCRYPT");
    }

    @Test
    public void testInitWithValidCostFactor() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", 10);

        bcryptHashProvider.init(properties);

        Map<String, Object> params = bcryptHashProvider.getParameters();
        assertEquals(params.get("bcrypt.cost.factor"), 10);
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testInitWithInvalidCostFactorTooLow() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", 3);

        bcryptHashProvider.init(properties);
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testInitWithInvalidCostFactorTooHigh() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", 32);

        bcryptHashProvider.init(properties);
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testInitWithNonIntegerCostFactor() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", "invalid");

        bcryptHashProvider.init(properties);
    }

    @Test
    public void testCalculateHashWithValidInput() throws Exception {
        char[] password = "testPassword123".toCharArray();

        byte[] hash = bcryptHashProvider.calculateHash(password, validSalt);

        assertNotNull(hash);
        assertTrue(hash.length > 0);
        assertTrue(new String(hash, StandardCharsets.UTF_8).startsWith("$2a$"));
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testCalculateHashWithNullPassword() throws Exception {
        bcryptHashProvider.calculateHash(null, validSalt);
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testCalculateHashWithEmptyPassword() throws Exception {
        bcryptHashProvider.calculateHash(new char[0], validSalt);
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testCalculateHashWithNullSalt() throws Exception {
        char[] password = "testPassword".toCharArray();
        bcryptHashProvider.calculateHash(password, null);
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testCalculateHashWithEmptySalt() throws Exception {
        char[] password = "testPassword".toCharArray();
        bcryptHashProvider.calculateHash(password, "");
    }

    @Test(expectedExceptions = HashProviderClientException.class)
    public void testCalculateHashWithInvalidSaltLength() throws Exception {
        char[] password = "testPassword".toCharArray();
        byte[] invalidSalt = new byte[8]; // Too short
        String salt = Base64.getEncoder().encodeToString(invalidSalt);

        bcryptHashProvider.calculateHash(password, salt);
    }

    @Test(expectedExceptions = HashProviderServerException.class)
    public void testCalculateHashWithMalformedBase64Salt() throws Exception {
        char[] password = "testPassword".toCharArray();
        String invalidSalt = "not-valid-base64!!";

        bcryptHashProvider.calculateHash(password, invalidSalt);
    }

    // Test for 72-byte limit scenarios
    @DataProvider(name = "passwordLengthProvider")
    public Object[][] passwordLengthProvider() {
        return new Object[][] {
                // Password that exactly hits 72 bytes in UTF-8
                {create72BytePassword(), true},
                // Password that exceeds 72 bytes (73 bytes)
                {create73BytePassword(), false},
                // Password with multi-byte characters
                {createMultiBytePassword(), true}
        };
    }

    @Test(dataProvider = "passwordLengthProvider")
    public void testPasswordByteLengthValidation(char[] password, boolean shouldSucceed) throws Exception {
        if (shouldSucceed) {
            byte[] hash = bcryptHashProvider.calculateHash(password, validSalt);
            assertNotNull(hash);
        } else {
            try {
                bcryptHashProvider.calculateHash(password, validSalt);
                fail("Expected HashProviderClientException for password exceeding 72 bytes");
            } catch (HashProviderClientException e) {
                assertTrue(e.getMessage().contains("72-byte limit"));
            }
        }
    }

    @Test
    public void testGetAlgorithm() {
        assertEquals(bcryptHashProvider.getAlgorithm(), "BCRYPT");
    }

    @Test
    public void testGetParameters() {
        Map<String, Object> params = bcryptHashProvider.getParameters();
        assertEquals(params.get(Constants.COST_FACTOR_PROPERTY), Constants.DEFAULT_COST_FACTOR);
        assertEquals(params.get(Constants.VERSION_PROPERTY), Constants.DEFAULT_BCRYPT_VERSION);
        assertEquals(params.size(), 2);
    }

    @Test
    public void testSamePasswordSameSaltProducesSameHash() throws Exception {
        char[] password = "testPassword".toCharArray();

        byte[] hash1 = bcryptHashProvider.calculateHash(password, validSalt);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, validSalt);

        assertNotNull(hash1);
        assertNotNull(hash2);
        assertEquals(hash1, hash2);
    }

    @Test
    public void testDifferentSaltsProduceDifferentHashes() throws Exception {
        char[] password = "testPassword".toCharArray();

        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        java.security.SecureRandom.getInstanceStrong().nextBytes(salt1);
        java.security.SecureRandom.getInstanceStrong().nextBytes(salt2);

        String saltStr1 = Base64.getEncoder().encodeToString(salt1);
        String saltStr2 = Base64.getEncoder().encodeToString(salt2);

        byte[] hash1 = bcryptHashProvider.calculateHash(password, saltStr1);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, saltStr2);

        assertNotNull(hash1);
        assertNotNull(hash2);
        assertNotEquals(hash1, hash2);
    }

    @Test
    public void testVeryShortPassword() throws Exception {
        char[] password = "a".toCharArray();
        byte[] hash = bcryptHashProvider.calculateHash(password, validSalt);
        assertNotNull(hash);
        assertTrue(hash.length > 0);
    }

    @Test
    public void testPasswordWithSpecialCharacters() throws Exception {
        char[] password = "p@ssw0rd!@#$%^&*()".toCharArray();
        byte[] hash = bcryptHashProvider.calculateHash(password, validSalt);
        assertNotNull(hash);
        assertTrue(hash.length > 0);
    }

    @Test
    public void testPasswordWithUnicodeCharacters() throws Exception {
        char[] password = "密码🔑测试".toCharArray();
        byte[] hash = bcryptHashProvider.calculateHash(password, validSalt);
        assertNotNull(hash);
        assertTrue(hash.length > 0);
    }

    @Test
    public void testHashStructureValidation() throws Exception {
        char[] password = "testPassword".toCharArray();
        byte[] hashBytes = bcryptHashProvider.calculateHash(password, validSalt);
        String hashString = new String(hashBytes, StandardCharsets.UTF_8);

        // Verify BCrypt hash structure
        assertTrue(hashString.startsWith("$2a$"));
        assertTrue(hashString.length() >= 60); // Minimum BCrypt hash length
        assertEquals(hashString.split("\\$").length, 4);
    }

    // Helper methods for creating test passwords
    private char[] create72BytePassword() {
        // Create a string that exactly equals 72 bytes in UTF-8
        StringBuilder sb = new StringBuilder();
        while (sb.toString().getBytes(StandardCharsets.UTF_8).length < 72) {
            sb.append("a");
        }
        // Trim to exactly 72 bytes
        while (sb.toString().getBytes(StandardCharsets.UTF_8).length > 72) {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString().toCharArray();
    }

    private char[] create73BytePassword() {
        char[] password = create72BytePassword();
        // Add one more character to exceed 72 bytes
        return (new String(password) + "a").toCharArray();
    }

    private char[] createMultiBytePassword() {
        // Use characters that take multiple bytes in UTF-8
        return "测试密码123".toCharArray(); // Chinese characters + numbers
    }
}