# Kernel OpenID Bridge API

## Overview

This library provides server-side functions related to login using the **Authorization Code Flow**. The Authorization Code grant type is used by confidential and public clients to exchange an authorization code for an access token. For an overview on Authorization Code grant type, [refer here](https://oauth.net/2/grant-types/authorization-code/).

## Features

- Provides REST APIs for login, logout, and online token validation functionalities.

## Local Setup

### Usage

1. To use this API, add it to your project's dependency list:

```xml
<dependency>
    <groupId>io.mosip.kernel</groupId>
    <artifactId>kernel-openid-bridge-api</artifactId>
    <version>${project.version}</version>
</dependency>
```

## Configuration

### Properties

Add the following properties to your configuration:

```properties
auth.server.admin.validate.url=https://<host>/v1/authmanager/authorize/admin/validateToken
mosip.iam.module.clientID=<module-client-id>
mosip.iam.module.clientsecret=<module-client-secret>
mosip.iam.module.redirecturi=https://<host>/<context-path>/login-redirect/	
mosip.iam.module.admin_realm_id=<realm-id>	
mosip.iam.base-url=<iam-bas-url>	
mosip.iam.authorization_endpoint=${mosip.iam.base-url}/auth/realms/{realmId}/protocol/openid-connect/auth
mosip.iam.token_endpoint=${mosip.iam.base-url}/auth/realms/{realmId}/protocol/openid-connect/token
```

### Bean Scanning

Add the following package to scan for beans:

```java
io.mosip.kernel-openid-bridge-api.*
```

## Documentation

For technical details, refer to the [MOSIP Kernel OpenID Bridge API Documentation](https://mosip.github.io/documentation/1.2.0/kernel-authentication-manager-service.html).

## Contribution & Community

• To learn how you can contribute code to this application, [click here](https://docs.mosip.io/1.2.0/community/code-contributions).

• If you have questions or encounter issues, visit the [MOSIP Community](https://community.mosip.io/) for support.

• For any GitHub issues: [Report here](https://github.com/mosip/mosip-openid-bridge/issues)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).