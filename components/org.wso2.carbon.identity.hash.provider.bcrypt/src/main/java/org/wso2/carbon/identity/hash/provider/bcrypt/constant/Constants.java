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

package org.wso2.carbon.identity.hash.provider.bcrypt.constant;

/**
 * This class contains constants.
 */
public class Constants {

//    public static final String PBKDF2_HASH_PROVIDER_ERROR_PREFIX = "PB2-";
//
//    public static final String PSEUDO_RANDOM_FUNCTION_PROPERTY = "pbkdf2.prf";
//    public static final String ITERATION_COUNT_PROPERTY = "pbkdf2.iteration.count";
//    public static final String DERIVED_KEY_LENGTH_PROPERTY = "pbkdf2.dkLength";
//
//    public static final String PBKDF2_HASHING_ALGORITHM = "PBKDF2";
//    public static final String DEFAULT_PBKDF2_PRF = "PBKDF2WithHmacSHA256";
//    public static final int DEFAULT_ITERATION_COUNT = 10000;
//    public static final int DEFAULT_DERIVED_KEY_LENGTH = 256;


    public static final String BCRYPT_HASH_PROVIDER_ERROR_PREFIX = "BC-";

    public static final String COST_FACTOR_PROPERTY = "bcrypt.cost.factor";

    public static final String BCRYPT_HASHING_ALGORITHM = "BCRYPT";
    public static final int DEFAULT_COST_FACTOR = 12;


    private Constants() {

    }
}

