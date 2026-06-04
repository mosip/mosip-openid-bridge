# AGENTS.md — mosip-openid-bridge
This file provides guidance to AI agents when working with code in this repository.

## Project Overview
MOSIP OpenID Bridge provides authentication and authorization services for the MOSIP (Modular Open-Source Identification Platform). It bridges MOSIP's internal auth mechanisms with OpenID Connect / OAuth 2.0 flows, supporting ID lifecycle management (registration, update, authentication, deactivation of identities via Keycloak).

**GitHub:** https://github.com/mosip/mosip-openid-bridge  
**License:** Mozilla Public License 2.0 
---

## Module Structure

Multi-module Maven project rooted at `kernel/pom.xml`.

| Module | Type | Purpose |
|--------|------|---------|
| `kernel-openid-bridge-api` | JAR library | Server-side OpenID Connect / auth code flow support; shared constants, DTOs, service interfaces |
| `kernel-authcodeflowproxy-api` | JAR library | OAuth 2.0 Authorization Code Flow proxy; login/logout/token-validation REST APIs |
| `kernel-auth-adapter` | JAR library | Spring Security adapter injected into MOSIP services to secure their REST APIs |
| `kernel-auth-service` | Spring Boot app | Runnable auth manager service; port 8091, context `/v1/authmanager` |

---

## Build

**Requirements:** Java 21, Maven 3.9.6+

```bash
# Build all modules (skip GPG signing for local dev)
cd kernel
mvn install -Dgpg.skip=true

# Build + test a single module
mvn clean package -pl kernel-auth-service

# Skip tests
mvn install -DskipTests -Dgpg.skip=true

# Run all tests
mvn test
```

**CI:** GitHub Actions (`.github/workflows/push-trigger.yml`) — builds Docker image, runs SonarCloud analysis, publishes to Maven Central via Sonatype OSSRH.

---

## Key Source Locations

### kernel-auth-service (runnable service)
- Entry point: `kernel/kernel-auth-service/src/main/java/io/mosip/kernel/auth/AuthBootApplication.java`
- Main controller: `.../auth/controller/AuthController.java`
- IAM/Keycloak impl: `.../auth/defaultimpl/repository/impl/KeycloakImpl.java`
- IAM HTTP config: `.../auth/defaultimpl/config/DefaultImplIAMConfiguration.java` (Apache HC5 connection pool)
- Token validation: `.../auth/defaultimpl/util/TokenValidator.java`

### kernel-auth-adapter (security adapter library)
- Security filter: `.../defaultadapter/filter/AuthFilter.java`
- Token validation: `.../defaultadapter/helper/TokenValidationHelper.java`
- Self-token renewal: `.../defaultadapter/config/SelfTokenRenewalTaskExecutor.java`
- No-auth endpoints: `.../defaultadapter/config/NoAuthenticationEndPoint.java`
- Token exchange: `.../defaultadapter/config/SelfTokenExchangeFilterFunction.java`

### kernel-authcodeflowproxy-api
- Controller: `.../authcodeflowproxy/api/controller/LoginController.java`
- Service impl: `.../authcodeflowproxy/api/service/impl/LoginServiceImpl.java`
- Token util: `.../authcodeflowproxy/api/validator/ValidateTokenUtil.java`

### kernel-openid-bridge-api
- Constants: `.../openid/bridge/api/constants/Constants.java`
- Service interfaces: `.../openid/bridge/api/service/` (AuthNService, AuthService, LoginService, etc.)

---

## Configuration

### kernel-auth-service runtime config
- `kernel/kernel-auth-service/src/main/resources/bootstrap.properties` — Spring Cloud Config URL and profile
- `kernel/kernel-auth-service/src/main/resources/application-local.properties` — local dev overrides

Key properties:
```properties
server.port=8091
server.servlet.context-path=/v1/authmanager
auth.jwt.expiry=1800000
auth.jwt.refresh.expiry=86400000
mosip.keycloak.admin.client.id=admin-cli
```

### kernel-auth-adapter config
- `kernel/kernel-auth-adapter/src/main/resources/application.yml` — global no-auth endpoint patterns, CORS

---

## Docker & Helm

- **Dockerfile:** `kernel/kernel-auth-service/Dockerfile`  
  Base: `eclipse-temurin:21-jre-alpine`, port 8091, user `mosip` (UID 1002)
- **Helm chart:** `helm/authmanager/` — version `0.0.1-develop` on develop branch
- **Deploy script:** `deploy/install.sh` — uses `CHART_VERSION=0.0.1-develop`

```bash
helm repo add mosip https://mosip.github.io
helm install authmanager mosip/authmanager
```

---

## Key Dependencies

| Dependency | Version |
|-----------|--------|
| Java | 21 |
| Spring Boot | 3.2.3 |
| com.auth0:java-jwt | via kernel-bom |
| jwks-rsa | via kernel-bom |
| Apache HttpComponents 5 (HC5) | via kernel-bom |
| Keycloak adapter BOM | 6.0.1 |
| springdoc-openapi | 2.6.0 |

**Note:** `DateUtils2` (not `DateUtils`) is used throughout — it is from `kernel-core`. Ensure `kernel.core.version` resolves to a version that includes `DateUtils2`.

---

## MOSIP ID Lifecycle Context

This service supports identity lifecycle management for MOSIP:
- **Registration:** Keycloak user creation, token issuance for new identities
- **Authentication:** JWT token generation/validation for service-to-service calls
- **Authorization Code Flow:** Browser-based OIDC login via `kernel-authcodeflowproxy-api`
- **Token renewal:** Automatic self-token refresh via `SelfTokenRenewalTaskExecutor`
- **Identity deactivation:** Managed via Keycloak user state changes

---

## Branch & Version Conventions

| Branch | Purpose |
|--------|---------|
| `master` | Stable release |
| `develop` | Active development  |
| `release-*` / `1.*` | Release branches |
| `rel-*-test` | Test branches for merge validation |


---

## Testing

```bash
# All tests
cd kernel && mvn test

# Module-specific
mvn test -pl kernel-auth-adapter
mvn test -pl kernel-auth-service

# Single test class
mvn test -pl kernel-auth-service -Dtest=KeycloakImplTest
```

Test classes are under `src/test/java/` in each module. Framework: JUnit 4, Mockito, PowerMock.

---

## Common Pitfalls

- `DateUtils` was replaced by `DateUtils2` across the codebase — always use `DateUtils2` for date operations
- GPG signing is enabled for Maven Central publishing — pass `-Dgpg.skip=true` for all local builds
- pom.xml parent versions for `kernel-bom` use `${kernel.core.version}` — keep this property consistent with the project version line