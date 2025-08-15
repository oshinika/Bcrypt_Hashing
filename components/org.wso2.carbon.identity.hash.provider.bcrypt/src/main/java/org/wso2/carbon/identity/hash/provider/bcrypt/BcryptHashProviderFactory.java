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

import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;
import org.wso2.carbon.user.core.hash.HashProviderFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The class contains the implementation of PBKDF2 HashProvider Factory.
 */
public class BcryptHashProviderFactory implements HashProviderFactory {

    @Override
    public HashProvider getHashProvider() {

        BcryptHashProvider pbkdf2HashProvider = new BcryptHashProvider();
        pbkdf2HashProvider.init();
        return pbkdf2HashProvider;
    }

    @Override
    public HashProvider getHashProvider(Map<String, Object> initProperties) throws HashProviderException {

        BcryptHashProvider pbkdf2HashProvider = new BcryptHashProvider();
        pbkdf2HashProvider.init(initProperties);
        return pbkdf2HashProvider;
    }

    @Override
    public Set<String> getHashProviderConfigProperties() {

        Set<String> metaProperties = new HashSet<>();
        metaProperties.add(Constants.ITERATION_COUNT_PROPERTY);
        metaProperties.add(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);
        metaProperties.add(Constants.DERIVED_KEY_LENGTH_PROPERTY);
        return metaProperties;
    }

    @Override
    public String getAlgorithm() {

        return Constants.PBKDF2_HASHING_ALGORITHM;
    }
}
