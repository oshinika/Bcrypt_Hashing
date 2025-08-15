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
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;

import java.util.HashMap;
import java.util.Map;

/**
 * Test class for PBKDF2HashProvider.
 */
public class PBKDF2HashProviderTest {

    private static BcryptHashProvider pbkdf2HashProvider = null;
    private static Map<String, Object> initProperties;

    @BeforeClass
    public void initialize() {

        pbkdf2HashProvider = new BcryptHashProvider();
    }

    @DataProvider(name = "initConfig")
    public Object[][] initConfig() {

        pbkdf2HashProvider.init();
        initProperties = pbkdf2HashProvider.getParameters();
        int iterationCount = (int) initProperties.get(Constants.ITERATION_COUNT_PROPERTY);
        int dkLength = (int) initProperties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY);
        String pseudoRandomFunction = (String) initProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);

        return new Object[][]{
                {iterationCount, Constants.DEFAULT_ITERATION_COUNT},
                {dkLength, Constants.DEFAULT_DERIVED_KEY_LENGTH},
                {pseudoRandomFunction, Constants.DEFAULT_PBKDF2_PRF}
        };
    }

    @Test(dataProvider = "initConfig")
    public void testInitConfig(Object parameters, Object expectedValue) {

        Assert.assertEquals(parameters, expectedValue);
    }

    @DataProvider(name = "initConfigParams")
    public Object[][] initConfigParams() {

        return new Object[][]{
                {"10000", "160", "PBKDF2WithHmacSHA1"},
                {"25000", "512", "PBKDF2WithHmacSHA256"},
                {null, "256", "PBKDF2WithHmacSHA512"},
                {"10000", null, "PBKDF2WithHmacSHA256"},
                {"20000", "256", null}
        };
    }

    @Test(dataProvider = "initConfigParams")
    public void testInitConfigParams(String iterationCount, String dkLength, String pseudoRandomFunction)
            throws HashProviderException {

        Map<String, Object> initProperties = new HashMap<>();

        if (pseudoRandomFunction != null) {
            initProperties.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        }
        if (dkLength != null) {
            initProperties.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        }
        if (iterationCount != null) {
            initProperties.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        }
        pbkdf2HashProvider.init(initProperties);
        Map<String, Object> pbkdf2Params = pbkdf2HashProvider.getParameters();
        if (iterationCount == null) {
            Assert.assertEquals(pbkdf2Params.get(Constants.ITERATION_COUNT_PROPERTY),
                    Constants.DEFAULT_ITERATION_COUNT);
        } else {
            Assert.assertEquals(pbkdf2Params.get(Constants.ITERATION_COUNT_PROPERTY), Integer.parseInt(iterationCount));
        }
        if (dkLength == null) {
            Assert.assertEquals(pbkdf2Params.get(Constants.DERIVED_KEY_LENGTH_PROPERTY),
                    Constants.DEFAULT_DERIVED_KEY_LENGTH);
        } else {
            Assert.assertEquals(pbkdf2Params.get(Constants.DERIVED_KEY_LENGTH_PROPERTY), Integer.parseInt(dkLength));
        }
        if (pseudoRandomFunction == null) {
            Assert.assertEquals(pbkdf2Params.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY),
                    Constants.DEFAULT_PBKDF2_PRF);
        } else {
            Assert.assertEquals(pbkdf2Params.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY), pseudoRandomFunction);
        }
    }

    @DataProvider(name = "getHash")
    public Object[][] getHash() {

        return new Object[][]{
                {"vijee123".toCharArray(), "GzgyTT0M0TSvgMaXZEbD1Q==", "20000", "128", "PBKDF2WithHmacSHA256",
                        hexStringToByteArray("768b3558e3b5dc7bf4d5b27da4b71dee")},
                {"nisho123".toCharArray(), "GzgyTT0M0TSvgMaXZEbD1Q==", "10000", "256", "PBKDF2WithHmacSHA256",
                        hexStringToByteArray(
                                "295fe5dbc666f75b31ff15a57b2582968a0f7dc6f53cd6799c0d0e3971626061")},
                {"john123".toCharArray(), "GzgyTT0IOweHJgcXZEbD1Q==", "25000", "512", "PBKDF2WithHmacSHA1",
                        hexStringToByteArray(
                                "fad16c9ffc6f877b4b2cfada3596dcef4259ccaa7240c1a9ac64731b58c0c0" +
                                        "d59653cf98e599f84212ea52fdcd507d7063d9601444594ff817a5de6f930ee374")}
        };
    }

    @Test(dataProvider = "getHash")
    public void testGetHash(char[] plainText, String salt, String iterationCount, String dkLength,
                            String pseudoRandomFunction, byte[] hash) throws HashProviderException {

        initializeHashProvider(iterationCount, dkLength, pseudoRandomFunction);
        Assert.assertEquals(pbkdf2HashProvider.calculateHash(plainText, salt), hash);
    }

    @DataProvider(name = "hashProviderErrorScenarios")
    public Object[][] hashProviderErrorScenarios() {

        return new Object[][]{
                {"".toCharArray(), "GzgyTT0M0TSvgMaXZEbD1Q==", "20000", "128", "PBKDF2WithHmacSHA256",
                        ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode()},
                {"wso2123".toCharArray(), "", "10000", "256", "PBKDF2WithHmacSHA256",
                        ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getCode()},
                {"    ".toCharArray(), "GzgyTT0M0TSvgMaXZEbD1Q==", "20000", "128", "PBKDF2WithHmacSHA256",
                        ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode()},
                {"john12".toCharArray(), "    ", "10000", "256", "PBKDF2WithHmacSHA256",
                        ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getCode()},
                {"qwerty".toCharArray(), "GzgyTT0M0TSvgMaXZEbD1Q==", "1000", "256", "Algo",
                        ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getCode()},
        };
    }

    @Test(dataProvider = "hashProviderErrorScenarios")
    public void testHashProviderErrorScenarios(char[] plainText, String salt, String iterationCount, String dkLength,
                                               String pseudoRandomFunction, String errorCodeExpected)
            throws HashProviderException {

        try {
            initializeHashProvider(iterationCount, dkLength, pseudoRandomFunction);
            pbkdf2HashProvider.calculateHash(plainText, salt);
        } catch (HashProviderClientException e) {
            Assert.assertEquals(e.getErrorCode().substring(4), errorCodeExpected);
        } catch (HashProviderServerException e) {
            Assert.assertEquals(e.getErrorCode().substring(4), errorCodeExpected);
        }
    }

    @Test
    public void testGetAlgorithm() {

        Assert.assertEquals(pbkdf2HashProvider.getAlgorithm(), Constants.PBKDF2_HASHING_ALGORITHM);
    }

    /**
     * Convert hexadecimal format string to byte array.
     *
     * @param hexadecimal Hexadecimal format string.
     * @return Converted byte array.
     */
    private static byte[] hexStringToByteArray(String hexadecimal) {

        int len = hexadecimal.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexadecimal.charAt(i), 16) << 4)
                    + Character.digit(hexadecimal.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Initializing the HashProvider with given meta properties.
     *
     * @param iterationCount       The iteration count.
     * @param dkLength             The derived key length.
     * @param pseudoRandomFunction The pseudo random function.
     */
    private void initializeHashProvider(String iterationCount, String dkLength, String pseudoRandomFunction)
            throws HashProviderException {

        initProperties = new HashMap<>();
        initProperties.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        initProperties.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        initProperties.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        pbkdf2HashProvider.init(initProperties);
    }
}
