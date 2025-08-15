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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Test class for PBKDF2HashProviderFactory.
 */
public class PBKDF2HashProviderFactoryTest {

    private static BcryptHashProviderFactory pbkdf2HashProviderFactory = null;
    private static HashProvider pbkdf2HashProvider = null;

    @BeforeClass
    public void initialize() {

        pbkdf2HashProviderFactory = new BcryptHashProviderFactory();
    }

    @Test
    public void testGetConfigProperties() {

        Set<String> metaPropertiesActual = pbkdf2HashProviderFactory.getHashProviderConfigProperties();
        Set<String> metaPropertiesExpected = new HashSet<>();
        metaPropertiesExpected.add(Constants.ITERATION_COUNT_PROPERTY);
        metaPropertiesExpected.add(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);
        metaPropertiesExpected.add(Constants.DERIVED_KEY_LENGTH_PROPERTY);
        Assert.assertEquals(metaPropertiesActual, metaPropertiesExpected);
    }

    @Test
    public void testGetAlgorithm() {

        Assert.assertEquals(pbkdf2HashProviderFactory.getAlgorithm(), Constants.PBKDF2_HASHING_ALGORITHM);
    }

    @Test
    public void testGetHashProviderWithDefaultParams() {

        pbkdf2HashProvider = pbkdf2HashProviderFactory.getHashProvider();
        Map<String, Object> pbkdf2ParamsMap = pbkdf2HashProvider.getParameters();
        Assert.assertEquals(pbkdf2ParamsMap.get(Constants.ITERATION_COUNT_PROPERTY), Constants.DEFAULT_ITERATION_COUNT);
        Assert.assertEquals(pbkdf2ParamsMap.get(Constants.DERIVED_KEY_LENGTH_PROPERTY),
                Constants.DEFAULT_DERIVED_KEY_LENGTH);
        Assert.assertEquals(pbkdf2ParamsMap.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY),
                Constants.DEFAULT_PBKDF2_PRF);
    }

    @DataProvider(name = "getHashProviderWithParams")
    public Object[][] getHashProviderWithParams() {

        return new Object[][]{
                {"5000", "160", "PBKDF2WithHmacSHA1"},
                {"15000", "512", "PBKDF2WithHmacSHA512"}
        };
    }

    @Test(dataProvider = "getHashProviderWithParams")
    public void testGetHashProviderWithParams(String iterationCount, String dkLength, String pseudoRandomFunction)
            throws HashProviderException {

        Map<String, Object> pbkdf2Params = new HashMap<>();
        pbkdf2Params.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        pbkdf2Params.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        pbkdf2Params.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        pbkdf2HashProvider = pbkdf2HashProviderFactory.getHashProvider(pbkdf2Params);
        Assert.assertEquals(pbkdf2HashProvider.getParameters().get(Constants.ITERATION_COUNT_PROPERTY),
                Integer.parseInt(iterationCount));
        Assert.assertEquals(pbkdf2HashProvider.getParameters().get(Constants.DERIVED_KEY_LENGTH_PROPERTY),
                Integer.parseInt(dkLength));
        Assert.assertEquals(pbkdf2HashProvider.getParameters().get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY),
                pseudoRandomFunction);
    }
}
