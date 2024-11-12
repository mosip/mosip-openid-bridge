[![Maven Package upon a push](https://github.com/mosip/mosip-openid-bridge/actions/workflows/push_trigger.yml/badge.svg?branch=develop)](https://github.com/mosip/mosip-openid-bridge/actions/workflows/push_trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mosip_mosip-openid-bridge&metric=alert_status)](https://sonarcloud.io/dashboard?branch=develop&id=mosip_mosip-openid-bridge)

# MOSIP OpenID Bridge

## Overview
Contains the following components:

1. [Kernel Auth Adapter](kernel/kernel-auth-adapter)
2. [Kernel Auth Service](kernel/kernel-auth-service)

## Functionality
-  Generate token using userid and password.
-  Generate token using client-id and secret key.
-  Validate token.
-  Refresh token.
-  Invalidate token on token expiry.

## APIs
API documentation is available [here](https://mosip.github.io/documentation/1.2.0/kernel-authentication-manager-service.html).

## Deploy
To deploy Auth Service on Kubernetes cluster using Dockers refer to [Sandbox Deployment](https://docs.mosip.io/1.2.0/deploymentnew/v3-installation).

## License
This project is licensed under the terms of [Mozilla Public License 2.0](LICENSE)
