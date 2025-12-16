# Kernel Auth Service

## Overview

The **Kernel Auth Service** provides REST APIs to authenticate MOSIP services. It handles token generation, validation, and lifecycle management.

## Features

- Generate token using userid and password
- Generate token using client-id and secret key
- Validate token
- Refresh token
- Invalidate token on token expiry

## Database
NA (Not applicable)

## Local Setup

The project can be set up in two ways:
1. [Local Setup (for Development)](#local-setup-for-development)
2. [Local Setup with Docker](#local-setup-with-docker)

### Prerequisites

- **JDK**: 21.0.3
- **Maven**: 3.9.6
- **Docker**: Latest stable version

### Configuration

- Kernel Auth Service uses configuration files from the **[mosip-config repository](https://github.com/mosip/mosip-config/tree/master)**.
- Refer to the tagged version corresponding to your release.
- Key configuration files:
    - [application-default.properties](https://github.com/mosip/mosip-config/blob/master/application-default.properties)
    - [kernel-default.properties](https://github.com/mosip/mosip-config/blob/master/kernel-default.properties)

## Installation

### Local Setup (for Development)

1. Ensure the **Config Server** is running and accessible.

2. Navigate to the kernel directory and build:

```bash
cd kernel
mvn install -Dgpg.skip=true
```

### Local Setup with Docker

1. Build the Docker image:

```bash
cd kernel/kernel-auth-service
docker build -f Dockerfile .
```

2. Run the service container (ensure appropriate environment variables and network settings are configured).

## Deployment

### Kubernetes

To deploy Auth Service on a Kubernetes cluster, refer to the [Sandbox Deployment Guide](https://docs.mosip.io/1.2.0/deploymentnew/v3-installation).

## Documentation

### API Documentation

API documentation is available at: [MOSIP Kernel Authentication Manager Service](https://mosip.github.io/documentation/1.2.0/kernel-authentication-manager-service.html).

### Product Documentation

For functional details, refer to: [Module Configuration](https://docs.mosip.io/1.2.0/modules/module-configuration).

## Contribution & Community

• To learn how you can contribute code to this application, [click here](https://docs.mosip.io/1.2.0/community/code-contributions).

• If you have questions or encounter issues, visit the [MOSIP Community](https://community.mosip.io/) for support.

• For any GitHub issues: [Report here](https://github.com/mosip/mosip-openid-bridge/issues)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
