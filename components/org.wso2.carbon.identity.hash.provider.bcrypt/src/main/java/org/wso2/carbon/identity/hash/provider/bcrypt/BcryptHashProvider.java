
/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.hash.provider.bcrypt;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants.BCRYPT_SALT_LENGTH;

/**
 * BCrypt password hashing implementation using OpenBSDBCrypt.
 */
public class BcryptHashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(BcryptHashProvider.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    private int costFactor;
    private String version;

    @Override
    public void init() {
        costFactor = Constants.DEFAULT_COST_FACTOR;
        version = Constants.DEFAULT_BCRYPT_VERSION;
    }

    @Override
    public void init(Map<String, Object> initProperties) throws HashProviderException {
        init();

        if (initProperties != null) {
            Object costFactorObject = initProperties.get(Constants.COST_FACTOR_PROPERTY);
            Object versionObject = initProperties.get(Constants.VERSION_PROPERTY);

            if (costFactorObject != null) {
                try {
                    costFactor = Integer.parseInt(costFactorObject.toString());
                    validateCostFactor(costFactor);
                } catch (NumberFormatException e) {
                    throw new HashProviderClientException(
                            "BCrypt cost factor must be an integer between 4-31. Got: " + costFactorObject, e);
                }
            }

            if (versionObject != null) {
                try {
                    version = versionObject.toString();
                    validateVersion(version);
                } catch (Exception e) {
                    throw new HashProviderClientException(
                            "BCrypt version must be a supported string ('2a', '2y', or '2b'). Got: " + versionObject, e);
                }
            }
        }
    }

    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {
        // Validate password is not null or empty
        if (plainText == null || plainText.length == 0) {
            throw new HashProviderClientException("Password cannot be null or empty");
        }

        // Generate salt if null or empty.
        String actualSalt = salt;
        if (StringUtils.isEmpty(actualSalt)) {
            actualSalt = generateSalt();
            if (log.isDebugEnabled()) {
                log.debug("Generated new salt since none was provided.");
            }
        } else {
            // Validate the provided salt.
            validateSalt(actualSalt);
        }

        int byteLength = getUtf8ByteLength(plainText);
        if (byteLength > Constants.BCRYPT_MAX_PLAINTEXT_LENGTH) {
            throw new HashProviderClientException(
                    "Password exceeds BCrypt's 72-byte limit. Length: " + byteLength + " bytes");
        }

        byte[] saltBytes;
        try {
            saltBytes = Base64.getDecoder().decode(actualSalt);
        } catch (IllegalArgumentException e) {
            String msg = "Invalid Base64 salt format.";
            log.error(msg, e);
            throw new HashProviderServerException(msg, e);
        }

        if (saltBytes.length != BCRYPT_SALT_LENGTH) {
            throw new HashProviderClientException(
                    "Salt must be exactly 16 bytes when decoded. Got: " + saltBytes.length + " bytes");
        }

        try {
            String bcryptHash = OpenBSDBCrypt.generate(version, plainText, saltBytes, costFactor);
            if (log.isDebugEnabled()) {
                log.debug("Generated BCrypt hash.");
            }
            return bcryptHash.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            String msg = "Error generating BCrypt hash.";
            log.error(msg, e);
            throw new HashProviderServerException(msg, e);
        }
    }

    @Override
    public Map<String, Object> getParameters() {
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        params.put(Constants.VERSION_PROPERTY, version);
        return params;
    }

    @Override
    public String getAlgorithm() {
        return Constants.BCRYPT_HASHING_ALGORITHM;
    }

    public boolean supportsValidateHash() {
        return true;
    }

    public boolean validateHash(char[] plainText, String storedHash, String salt) throws HashProviderException {
        // BCrypt's checkPassword method is self-contained and does not use a separate salt.
        // The salt is embedded in the storedHash.
        if (plainText == null || storedHash == null) {
            return false;
        }

        if (plainText.length == 0 || storedHash.length() != 60) {
            return false;
        }

        try {
            return OpenBSDBCrypt.checkPassword(storedHash, plainText);
        } catch (Exception e) {
            log.error("BCrypt validation error.", e);
            return false;
        }
    }

    /**
     * Generates a new random salt for hashing.
     *
     * @return The Base64 encoded salt string.
     */
    public String generateSalt() {
        byte[] saltBytes = new byte[BCRYPT_SALT_LENGTH];
        secureRandom.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    /**
     * Validate cost factor is within acceptable bounds (4-31).
     */
    private void validateCostFactor(int costFactor) throws HashProviderClientException {
        if (costFactor < 4) {
            throw new HashProviderClientException(
                    "BCrypt cost factor too low (minimum: 4). Low values compromise security.");
        }
        if (costFactor > 31) {
            throw new HashProviderClientException(
                    "BCrypt cost factor too high (maximum: 31). High values impact performance.");
        }
    }

    /**
     * Validate BCrypt version is supported.
     */
    private void validateVersion(String version) throws HashProviderClientException {
        if (version == null || (!version.equals("2a") && !version.equals("2y") && !version.equals("2b"))) {
            throw new HashProviderClientException(
                    "Unsupported BCrypt version. Must be '2a', '2y', or '2b'. Got: " + version);
        }
    }

    /**
     * Validate salt is not null and empty.
     */
    private void validateSalt(String salt) throws HashProviderClientException {
        if (salt == null) {
            throw new HashProviderClientException("Salt cannot be null.");
        }
        if (StringUtils.isEmpty(salt)) {
            throw new HashProviderClientException("Salt cannot be empty.");
        }
    }

    /**
     * Calculate UTF-8 byte length of password.
     */
    int getUtf8ByteLength(char[] chars) {
        if (chars == null || chars.length == 0) {
            return 0;
        }
        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
    }
}