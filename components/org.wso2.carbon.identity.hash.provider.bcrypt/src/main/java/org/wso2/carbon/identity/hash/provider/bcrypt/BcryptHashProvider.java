///*
// * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
// *
// * WSO2 Inc. licenses this file to you under the Apache License,
// * Version 2.0 (the "License"); you may not use this file except
// * in compliance with the License.
// * You may obtain a copy of the License at
// *
// * http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing,
// * software distributed under the License is distributed on an
// * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// * KIND, either express or implied.  See the License for the
// * specific language governing permissions and limitations
// * under the License.
// */
// // TODO : 2025 in all classes
//package org.wso2.carbon.identity.hash.provider.bcrypt;
//
////TODO : order imports
//import org.apache.commons.lang.ArrayUtils;
//import org.apache.commons.lang.StringUtils;
//import org.bouncycastle.crypto.generators.BCrypt;
//import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
//import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
//import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
//import org.wso2.carbon.user.core.exceptions.HashProviderException;
//import org.wso2.carbon.user.core.exceptions.HashProviderServerException;
//import org.wso2.carbon.user.core.hash.HashProvider;
//
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//
//import java.nio.charset.StandardCharsets;
//import java.security.SecureRandom;
//import java.util.Base64;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.Arrays;
//
//import static org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants.BCRYPT_MAX_PLAINTEXT_LENGTH;
//
///**
// * This class contains the implementation of the Bcrypt hashing algorithm.
// */
//public class BcryptHashProvider implements HashProvider {
//
//    private static final Log log = LogFactory.getLog(BcryptHashProvider.class);
//
//    private int costFactor;
//
//    @Override
//    public void init() {
//        costFactor = Constants.DEFAULT_COST_FACTOR;
//    }
//
//    @Override
//    public void init(Map<String, Object> initProperties) throws HashProviderException {
//        init();
//        Object costFactorObject = initProperties.get(Constants.COST_FACTOR_PROPERTY);
//
//        if (costFactorObject != null) {
//            try {
//                costFactor = Integer.parseInt(costFactorObject.toString());
//            } catch (NumberFormatException e) {
//                String msg = "Invalid value for the Bcrypt cost factor. It must be an integer.";
//                throw new HashProviderClientException(msg, e);
//            }
//            validateCostFactor(costFactor);
//        }
//    }
//
//    @Override
//    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {
//
//        //TODO: check is there a way to have a password more than 72 chars
//        // Validate password length based on byte size, not character count.
//        if (getByteLength(plainText) > BCRYPT_MAX_PLAINTEXT_LENGTH) {
//            String msg = "Password length exceeds the maximum allowed by Bcrypt (72 bytes).";
//            throw new HashProviderClientException(msg);
//        }
//
//        // TODO : reproduce OKTA issue
//        // TODO: correct the above code
//
//        try {
//            // Convert salt to bytes and ensure it's 16 bytes long
//            byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8); // TODO : check salt for null
//            // TODO : check for encoding decoding
//            // TODO : make the below logic configurable
//            if (saltBytes.length > 16) {
//                saltBytes = Arrays.copyOf(saltBytes, 16); // Truncate to 16 bytes
//            } else if (saltBytes.length < 16) {
//                // If shorter than 16 bytes, pad with zeros (though this case shouldn't happen)
//                saltBytes = Arrays.copyOf(saltBytes, 16);
//            }
//
//            String bcryptHash = OpenBSDBCrypt.generate(plainText, saltBytes, costFactor);
//            return bcryptHash.getBytes(StandardCharsets.UTF_8);
//        } catch (Exception e) { // TODO : exception type
//            String msg = "Error occurred while generating bcrypt hash.";
//            log.error(msg, e);
//            throw new HashProviderServerException(msg, e);
//        }
//    }
//
//    /**
//     * Helper method to get the byte length of a character array.
//     * @return The byte length of the character array.
//     */
//
//    @Override
//    public Map<String, Object> getParameters() {
//        Map<String, Object> bcryptHashProviderParams = new HashMap<>();
//        bcryptHashProviderParams.put(Constants.COST_FACTOR_PROPERTY, costFactor);
//        return bcryptHashProviderParams;
//    }
//
//    @Override
//    public String getAlgorithm() {
//        return Constants.BCRYPT_HASHING_ALGORITHM;
//    }
//
//    /**
//     * This method is responsible for validating the cost factor.
//     *
//     * @param costFactor The cost factor to be validated.
//     * @throws HashProviderClientException If the cost factor is less than or equal to zero.
//     */
//    private void validateCostFactor(int costFactor) throws HashProviderClientException {
//
//        if (costFactor <= 0) {
//            String msg = "Bcrypt cost factor must be a positive integer.";
//            throw new HashProviderClientException(msg);
//        }
//    }
//
//    /**
//     * Get the byte length of the character array.
//     *
//     * @param chars The character array.
//     * @return The byte length of the character array.
//     */
//    private int getByteLength(char[] chars) {
//
//        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
//    }
//}
//
//
//
//
//




/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import static org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants.version;

/**
 * BCrypt password hashing implementation using OpenBSDBCrypt.
 */
public class BcryptHashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(BcryptHashProvider.class);
    private static final SecureRandom secureRandom = new SecureRandom();


    private int costFactor;

    @Override
    public void init() {
        costFactor = Constants.DEFAULT_COST_FACTOR;
    }

    @Override
    public void init(Map<String, Object> initProperties) throws HashProviderException {
        init();
        Object costFactorObject = initProperties.get(Constants.COST_FACTOR_PROPERTY);

        if (costFactorObject != null) {
            try {
                costFactor = Integer.parseInt(costFactorObject.toString());
                validateCostFactor(costFactor);
            } catch (NumberFormatException e) {
                throw new HashProviderClientException(
                        "BCrypt cost factor must be an integer between 4-31. Got: " + costFactorObject, e);
            }
        }
    }

    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {
        validatePassword(plainText);

        // Validate password length based on UTF-8 byte size
        int byteLength = getUtf8ByteLength(plainText);
        if (byteLength > Constants.BCRYPT_MAX_PLAINTEXT_LENGTH) {
            throw new HashProviderClientException(
                    "Password exceeds BCrypt's 72-byte limit. Length: " + byteLength + " bytes");
        }

        try {
            byte[] saltBytes;

            if (StringUtils.isNotEmpty(salt)) {
                // Use provided salt (for migration and verification)
                saltBytes = Base64.getDecoder().decode(salt);
                if (saltBytes.length != BCRYPT_SALT_LENGTH) {
                    throw new HashProviderClientException(
                            "Salt must be exactly 16 bytes when decoded. Got: " + saltBytes.length + " bytes");
                }
            } else {
                // Generate new salt (for new password creation)
                saltBytes = generateSalt();
            }

            String bcryptHash = OpenBSDBCrypt.generate(version,plainText, saltBytes, costFactor);

            if (log.isDebugEnabled()) {
                log.debug("Generated BCrypt hash: " + bcryptHash);
                log.debug("Hash length: " + bcryptHash.length() + " characters");
            }

            return bcryptHash.getBytes(StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            String msg = "Invalid input for BCrypt hashing.";
            log.error(msg, e);
            throw new HashProviderClientException(msg, e);
        } catch (Exception e) {
            String msg = "Error generating BCrypt hash";
            log.error(msg, e);
            throw new HashProviderServerException(msg, e);
        }
    }

    /**
     * Generate a secure random salt for BCrypt (16 bytes required)
     */
    private byte[] generateSalt() {
        byte[] salt = new byte[BCRYPT_SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    @Override
    public Map<String, Object> getParameters() {
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        return params;
    }

    @Override
    public String getAlgorithm() {
        return Constants.BCRYPT_HASHING_ALGORITHM;
    }

    /**
     * Validate cost factor is within acceptable bounds (4-31)
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
     * Validate password is not null or empty
     */
    private void validatePassword(char[] plainText) throws HashProviderClientException {
        if (plainText == null || plainText.length == 0) {
            throw new HashProviderClientException("Password cannot be null or empty");
        }
    }

    /**
     * Calculate UTF-8 byte length of password
     */
    private int getUtf8ByteLength(char[] chars) {
        if (chars == null || chars.length == 0) {
            return 0;
        }
        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
    }
}
