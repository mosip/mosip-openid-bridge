# Kernel Auth Adapter

## Overview

The **Auth Adapter** is a library that can be injected into MOSIP's applications to secure exposed REST APIs. It acts as an adapter to facilitate authentication processes.

## Local Setup

### Usage

Add the Auth Adapter module to your project as a Maven dependency:

```xml
<dependency>
    <groupId>io.mosip.kernel</groupId>
    <artifactId>kernel-auth-adapter</artifactId>
    <version>${project.version}</version>
</dependency>
```

## Configuration

Ensure the following configurations are present in your application properties if required by the adapter (refer to `kernel-auth-service` for related configurations as this adapter often interfaces with it).

## Documentation

For integration details, refer to the [MOSIP Kernel Authentication Manager Service Documentation](https://mosip.github.io/documentation/1.2.0/kernel-authentication-manager-service.html).

## Contribution & Community

• To learn how you can contribute code to this application, [click here](https://docs.mosip.io/1.2.0/community/code-contributions).

• If you have questions or encounter issues, visit the [MOSIP Community](https://community.mosip.io/) for support.

• For any GitHub issues: [Report here](https://github.com/mosip/mosip-openid-bridge/issues)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
