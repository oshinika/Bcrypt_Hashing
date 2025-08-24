

/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 */
package org.wso2.carbon.identity.hash.provider.bcrypt;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.testng.Assert.*;

/**
 * Test class for BcryptHashProviderFactory.
 */
public class BcryptHashProviderFactoryTest {

    private BcryptHashProviderFactory factory;

    @BeforeMethod
    public void setUp() {
        factory = new BcryptHashProviderFactory();
    }

    @Test
    public void testGetHashProvider() {
        HashProvider provider = factory.getHashProvider();
        assertNotNull(provider);
        assertTrue(provider instanceof BcryptHashProvider);
        assertEquals(provider.getAlgorithm(), "BCRYPT");
    }

    @Test
    public void testGetHashProviderWithProperties() throws HashProviderException {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", 10);

        HashProvider provider = factory.getHashProvider(properties);
        assertNotNull(provider);
        assertTrue(provider instanceof BcryptHashProvider);
        assertEquals(provider.getAlgorithm(), "BCRYPT");
    }

    @Test(expectedExceptions = HashProviderException.class)
    public void testGetHashProviderWithInvalidProperties() throws HashProviderException {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", "invalid");

        factory.getHashProvider(properties);
    }

    @Test
    public void testGetHashProviderConfigProperties() {
        Set<String> configProperties = factory.getHashProviderConfigProperties();
        assertNotNull(configProperties);
        assertEquals(configProperties.size(), 2); // Changed from 1 to 2
        assertTrue(configProperties.contains("bcrypt.cost.factor"));
        assertTrue(configProperties.contains("bcrypt.version")); // Add version check
    }

    @Test
    public void testGetAlgorithm() {
        assertEquals(factory.getAlgorithm(), "BCRYPT");
    }

    @Test
    public void testMultipleInstancesAreDifferent() {
        HashProvider provider1 = factory.getHashProvider();
        HashProvider provider2 = factory.getHashProvider();

        assertNotSame(provider1, provider2);
        assertEquals(provider1.getAlgorithm(), provider2.getAlgorithm());
    }

    // Additional test cases to improve coverage
    @Test
    public void testGetHashProviderWithNullProperties() throws HashProviderException {
        HashProvider provider = factory.getHashProvider(null);
        assertNotNull(provider);
        assertTrue(provider instanceof BcryptHashProvider);
    }

    @Test
    public void testGetHashProviderWithEmptyProperties() throws HashProviderException {
        HashProvider provider = factory.getHashProvider(new HashMap<>());
        assertNotNull(provider);
        assertTrue(provider instanceof BcryptHashProvider);
    }

    @Test
    public void testGetHashProviderWithPropertiesContainingNull() throws HashProviderException {
        Map<String, Object> properties = new HashMap<>();
        properties.put("bcrypt.cost.factor", null);

        // Should use default value when cost factor is null
        HashProvider provider = factory.getHashProvider(properties);
        assertNotNull(provider);
        assertTrue(provider instanceof BcryptHashProvider);
    }

    @Test
    public void testFactorySingletonBehavior() {
        BcryptHashProviderFactory factory1 = new BcryptHashProviderFactory();
        BcryptHashProviderFactory factory2 = new BcryptHashProviderFactory();

        // Different factory instances should produce different providers
        HashProvider provider1 = factory1.getHashProvider();
        HashProvider provider2 = factory2.getHashProvider();

        assertNotSame(provider1, provider2);
    }
}