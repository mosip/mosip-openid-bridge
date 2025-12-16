# MOSIP OpenID Bridge

[![Maven Package upon a push](https://github.com/mosip/mosip-openid-bridge/actions/workflows/push-trigger.yml/badge.svg?branch=develop)](https://github.com/mosip/mosip-openid-bridge/actions/workflows/push-trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mosip_mosip-openid-bridge&metric=alert_status)](https://sonarcloud.io/dashboard?branch=develop&id=mosip_mosip-openid-bridge)

## Overview

The **MOSIP OpenID Bridge** provides authentication services and adapters for MOSIP. It includes components for handling OpenID Connect authentication flows and bridging with MOSIP's internal authentication mechanisms.

## Services

The MOSIP OpenID Bridge repository contains the following modules:

1. **[Kernel Auth Service](kernel/kernel-auth-service/README.md)** (`kernel-auth-service`) - REST API service to authenticate MOSIP services.
2. **[Kernel Auth Adapter](kernel/kernel-auth-adapter/README.md)** (`kernel-auth-adapter`) - Adapter for authentication.
3. **[Kernel OpenID Bridge API](kernel/kernel-openid-bridge-api/README.md)** (`kernel-openid-bridge-api`) - API definitions for the bridge.
4. **[Kernel Auth Code Flow Proxy API](kernel/kernel-authcodeflowproxy-api/README.md)** (`kernel-authcodeflowproxy-api`) - Proxy API for auth code flow.

> [!NOTE]
> For detailed setup, configuration, API documentation, and deployment instructions, please refer to the README files of the respective services listed above.

## Contribution & Community

• To learn how you can contribute code to this application, [click here](https://docs.mosip.io/1.2.0/community/code-contributions).

• If you have questions or encounter issues, visit the [MOSIP Community](https://community.mosip.io/) for support.

• For any GitHub issues: [Report here](https://github.com/mosip/mosip-openid-bridge/issues)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).