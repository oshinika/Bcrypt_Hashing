/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;
import org.wso2.carbon.user.core.hash.HashProvider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;

/**
 * This class contains the implementation of the Bcrypt hashing algorithm.
 */
public class BcryptHashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(BcryptHashProvider.class);
    // Bcrypt has a hard limit of 72 bytes for the plaintext password.
    private static final int BCRYPT_MAX_PLAINTEXT_LENGTH = 72;

    private int costFactor;

    @Override
    public void init() {
        // Set a default cost factor if no properties are provided.
        costFactor = Constants.DEFAULT_COST_FACTOR;
    }

    @Override
    public void init(Map<String, Object> initProperties) throws HashProviderException {
        init();
        Object costFactorObject = initProperties.get(Constants.COST_FACTOR_PROPERTY);

        if (costFactorObject != null) {
            try {
                costFactor = Integer.parseInt(costFactorObject.toString());
            } catch (NumberFormatException e) {
                String msg = "Invalid value for the Bcrypt cost factor. It must be an integer.";
                throw new HashProviderClientException(msg, e);
            }
            validateCostFactor(costFactor);
        }
    }

    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {
        // Validate password length based on byte size, not character count.
        if (getByteLength(plainText) > BCRYPT_MAX_PLAINTEXT_LENGTH) {
            String msg = "Password length exceeds the maximum allowed by Bcrypt (72 bytes).";
            throw new HashProviderClientException(msg);
        }

        try {
            // Convert salt to bytes and ensure it's 16 bytes long
            byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
            if (saltBytes.length > 16) {
                saltBytes = Arrays.copyOf(saltBytes, 16); // Truncate to 16 bytes
            } else if (saltBytes.length < 16) {
                // If shorter than 16 bytes, pad with zeros (though this case shouldn't happen)
                saltBytes = Arrays.copyOf(saltBytes, 16);
            }

            String bcryptHash = OpenBSDBCrypt.generate(plainText, saltBytes, costFactor);
            return bcryptHash.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            String msg = "Error occurred while generating bcrypt hash.";
            log.error(msg, e);
            throw new HashProviderServerException(msg, e);
        }
    }




    @Override
    public Map<String, Object> getParameters() {
        Map<String, Object> bcryptHashProviderParams = new HashMap<>();
        bcryptHashProviderParams.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        return bcryptHashProviderParams;
    }

    @Override
    public String getAlgorithm() {
        return Constants.BCRYPT_HASHING_ALGORITHM;
    }

    /**
     * This method is responsible for validating the cost factor.
     *
     * @param costFactor The cost factor to be validated.
     * @throws HashProviderClientException If the cost factor is less than or equal to zero.
     */
    private void validateCostFactor(int costFactor) throws HashProviderClientException {
        if (costFactor <= 0) {
            String msg = "Bcrypt cost factor must be a positive integer.";
            throw new HashProviderClientException(msg);
        }
    }

    /**
     * Get the byte length of the character array.
     *
     * @param chars The character array.
     * @return The byte length of the character array.
     */
    private int getByteLength(char[] chars) {
        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
    }
}

