# Kernel Auth Service

## Overview
Contains REST API's to authenticate MOSIP services.  The API documentation for this service is available [here](https://mosip.github.io/documentation/)

## Build & run (for developers)
The project requires JDK 21.0
and mvn version - 3.9.6
1. Build and install:
    ```
    $ cd kernel
    $ mvn install -DskipTests=true -Dmaven.javadoc.skip=true -Dgpg.skip=true
    ```

2. Build Docker for a service:
    ```
    $ cd <service folder>
    $ docker build -f Dockerfile
    ```

## Configuration files
Kernel Auth Service uses the following configuration files:
```
application-default.properties
kernel-default.properties
```
Need to run the config-server along with the files mentioned above in order to run the kernel-auth service.

## Configuration
[Configuration-Application](https://github.com/mosip/mosip-config/blob/release-1.3.x/application-default.properties) and
[Configuration-Kernel](https://github.com/mosip/mosip-config/blob/release-1.3.x/kernel-default.properties) defined here.

Refer [Module Configuration](https://docs.mosip.io/1.2.0/modules/module-configuration) for location of these files.
