# BCrypt Hashing

BCrypt is a modern password-hashing algorithm that is an excellent choice for securing user passwords.BCrypt hashing method can be used to securely store user passwords in user stores. This method helps to reduce the risk of brute-force attacks against user passwords.

This guide walks you through the steps of configuring BCrypt as the hashing algorithm of a JDBC user store.

> [!NOTE]
> Currently, BCrypt supports only JDBC user stores of WSO2 Identity Server.

## Configure BCrypt hashing

This section guides you on how to configure BCrypt hashing on primary and secondary JDBC user stores.

### BCrypt for primary JDBC user stores

1. Place the org.wso2.carbon.identity.hash.provider.bcrypt-0.1.0-SNAPSHOT.jar file into the       `<IS_HOME>/repository/components/dropins` directory. You can download the .jar file (``) from the     WSO2 Store.

> [!NOTE]
> BCrypt is supported by 
[primary JDBC user stores](https://is.docs.wso2.com/en/7.0.0/guides/users/user-stores/primary-user-store/configure-a-jdbc-user-store/) but must be enabled in the deployment.toml file before initial server startup. Since BCrypt automatically generates a unique, cryptographically strong salt for each password, you must also disable the user store's external salt handling for it to function correctly .

2. Open the deployment.toml file located in the `<IS_HOME>/repository/conf` directory.

3. Add the following configuration under the `[user_store.properties]` section. If the section does not exist, you can create it.

   ```bash
     [user_store.properties]
     PasswordDigest = "BCRYPT"
     StoreSaltedPassword = "false"
    "Hash.Algorithm.Properties" = "{bcrypt.version:2a,bcrypt.cost.factor:10}"
   ```

### BCrypt for secondary JDBC user stores

1. Login to the Identity Server management console (`https://<IS_HOST>:<PORT>/console`) and [create a JDBC user store](https://is.docs.wso2.com/en/7.0.0/guides/users/user-stores/configure-secondary-user-stores/).

2. Navigate to **User Attributes & Stores > User Stores**, select the secondary JDBC user store you have created.
   
3. Navigate to the **User** tab of the user store and expand the **Show more** section.

4. Find the "Enable Salted Passwords" property and toggle it off (set it to false).

5. Edit the following properties with the values given:

   <table>
    <thead>
    <tr class="header">
    <th>Property</th>
    <th>Value</th>
    <th>Description</th>
    </tr>
    </thead>
    <tbody>
    <tr class="odd">
    <td>Password Hashing Algorithm</td>
    <td>BCRYPT</td>
    <td>Name of the hashing algorithm supported by the user store.</td>
    </tr>
    <tr class="even">
    <td>UserStore Hashing Configurations</td>
    <td>{bcrypt.version:2b,bcrypt.cost.factor:12}</td>
    <td>Additional parameters required for password hashing algorithm. This should be given in JSON format.</td>
    </tr>
    </tbody>
    </table>

5. Click **Update** to save the configurations.

   Successful updation of these configurations will convert the password hashing algorithm of the user store to BCRYPT.

   ### BCrypt parameters

   When configuring the BCrypt hashing algorithm the following parameters must be specified in the configurations:

   
    <table>
    <thead>
    <tr class="header">
    <th>Parameter</th>
    <th>Parameter name</th>
    <th>Default Value</th>
    <th>Other Recommended Values</th>
    </tr>
    </thead>
    <tbody>
    <tr class="odd">
    <td>bcrypt.version</td>
    <td>Version of the BCrypt algorithm</td>
    <td>2b</td>
    <td>2a,2b,2y</td>
    </tr>
    <tr class="even">
    <td>bcrypt.cost.factor</td>
    <td>Cost factor of the BCrypt algorithm</td>
    <td>12</td>
    <td>4 - 31</td>
    </tr>
    </tbody>
    </table>
   
> [!NOTE]
> - You may also use an existing user store which does not have any users in it. If you already have users in the user store, once the hashing algorithm is configured these users will not be able to get authenticated.
>
> - Such cases will impact with bad user experience as the users will not get authenticated even when they try to login using the correct  credentials. Admins may use the following approaches to reset the user passwords after configuring the BCrypt hashing algorithm on an existing user store:
>   - Ask users to reset their own passwords.
>   - Trigger password reset for all accounts of the user store using [admin initiated password reset](https://is.docs.wso2.com/en/7.0.0/guides/users/manage-users/#reset-the-users-password).



