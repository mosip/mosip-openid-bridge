# Kernel Auth Service

## Overview
Contains REST API's to authenticate MOSIP services.  The API documentation for this service is available [here](https://mosip.github.io/documentation/)

## Build & run (for developers)
The project requires JDK 1.21.
and mvn version - 3.9.6
1. Build and install:
    ```
    $ cd kernel
    $ mvn install -DskipTests=true -Dmaven.javadoc.skip=true -Dgpg.skip=true
    ```

### Remove the version-specific suffix (PostgreSQL95Dialect) from the Hibernate dialect configuration
   ```
   hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
   ```
This is for better compatibility with future PostgreSQL versions.

### Configure ANT Path Matcher for Spring Boot 3.x compatibility.
   ```
   spring.mvc.pathmatch.matching-strategy=ANT_PATH_MATCHER
   ```
This is to maintain compatibility with existing ANT-style path patterns.

### Add auth-adapter in a class-path to run a kernel-auth service
   ```
   <dependency>
       <groupId>io.mosip.kernel</groupId>
       <artifactId>kernel-auth-adapter</artifactId>
       <version>${kernel.auth.adapter.version}</version>
   </dependency>
   ```

## Configuration files
Kernel Auth Service uses the following configuration files:
```
application-default.properties
kernel-default.properties
```
Need to run the config-server along with the files mentioned above in order to run the kernel-auth service.

## Configuration
[Configuration-Application](https://github.com/mosip/mosip-config/blob/develop/application-default.properties) and
[Configuration-Kernel](https://github.com/mosip/mosip-config/blob/develop/kernel-default.properties) defined here.

Refer [Module Configuration](https://docs.mosip.io/1.2.0/modules/module-configuration) for location of these files.
