# CLAUDE.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

**MOSIP OpenID Bridge** provides the authentication and authorization infrastructure for MOSIP (Modular Open Source Identity Platform). It bridges MOSIP's internal services with an external IAM (Keycloak) using OpenID Connect, and supplies reusable libraries so every MOSIP service can enforce token-based security consistently.

The repository builds with Java 21 and Maven, and all modules live under the `kernel/` directory.

## Modules

| Module | Artifact ID | Role |
|--------|-------------|------|
| `kernel-openid-bridge-api` | `kernel-openid-bridge-api` | API interfaces and shared models — `AuthService`, `AuthNService`, `AuthZService`, `LoginService`, DTOs, constants, `JWTUtils`, `AuthCodeProxyFlowUtils` |
| `kernel-authcodeflowproxy-api` | `kernel-authcodeflowproxy-api` | Spring Boot library that adds OAuth2 Authorization Code Flow endpoints (`/login/{redirectURI}`, `/login-redirect/{redirectURI}`, `/logout/user`, `/authorize/admin/validateToken`) to any MOSIP service that scans `io.mosip.kernel.authcodeflowproxy.api.*` |
| `kernel-auth-adapter` | `kernel-auth-adapter` | Spring Security adapter added as a dependency to MOSIP services; installs `AuthFilter` (token extraction from cookies → remote validation), `SecurityConfig`, CORS filter, and `RestTemplateInterceptor` / `SelfTokenRestInterceptor` for outbound service-to-service auth |
| `kernel-auth-service` | `kernel-auth-service` | The deployable Spring Boot service (`AuthBootApplication`); exposes the Auth Manager REST API at `/v1/authmanager/**`; the only runnable JAR in the repo |

Dependency direction: `kernel-auth-service` and `kernel-authcodeflowproxy-api` depend on `kernel-openid-bridge-api`; `kernel-auth-adapter` depends on `kernel-openid-bridge-api`.

## Build Commands

All commands run from the `kernel/` directory (the Maven parent):

```bash
# Full build (skip Javadoc and GPG for local dev)
mvn clean install -Dmaven.javadoc.skip=true -Dgpg.skip=true

# Run all tests
mvn test

# Run a single test class
mvn test -Dtest=ClassName

# Run a single test method
mvn test -Dtest=ClassName#methodName

# Build / test a single module only
mvn clean install -pl kernel-auth-service -am -Dmaven.javadoc.skip=true -Dgpg.skip=true

# Code coverage report (output: target/site/jacoco/index.html)
mvn clean verify

# SonarQube static analysis
mvn clean verify -Psonar
```

## Running the Auth Service Locally

The service requires a **Spring Cloud Config Server** before startup. Configuration is fetched from [mosip-config](https://github.com/mosip/mosip-config); the two key files are `application-default.properties` and `kernel-default.properties`.

```bash
cd kernel/kernel-auth-service
mvn spring-boot:run \
  -Dspring-boot.run.arguments="--spring.cloud.config.uri=http://localhost:51000/config \
    --spring.cloud.config.label=master \
    --spring.profiles.active=default"
```

Or with Docker:

```bash
cd kernel/kernel-auth-service
docker build -f Dockerfile .
```

Kubernetes deployment: `deploy/install.sh` (see `deploy/README.md`).

## Architecture

### Authentication Flows

**Service-to-service (client-credentials):** A MOSIP service calls `POST /v1/authmanager/authenticate/clientidsecretkey` with its `clientId`/`secretKey`. `AuthServiceImpl` forwards the request to Keycloak's token endpoint (`mosip.iam.open-id-url/token`) using the `client_credentials` grant and returns the access token in a cookie.

**User login (password):** `POST /v1/authmanager/authenticate/internal/useridPwd` — password grant against Keycloak.

**User login (OTP):** Two-step — `POST /authenticate/sendotp` dispatches an OTP via `OTPService` (SMS/email through kernel-notification-service), then `POST /authenticate/useridOTP` validates it and exchanges for a Keycloak token.

**Authorization Code Flow (browser UIs):** `kernel-authcodeflowproxy-api` handles the redirect dance. `/login/v2/{redirectURI}` generates a UUID `state`, stores it in a cookie, and redirects the browser to Keycloak's authorization endpoint. Keycloak redirects back to `/login-redirect/{redirectURI}`, where the service exchanges the `code` for tokens and sets the access token cookie.

**Token validation (inbound):** `kernel-auth-adapter`'s `AuthFilter` reads the `Authorization` cookie from every inbound request and calls `GET /v1/authmanager/authorize/admin/validateToken`. `AuthServiceImpl.valdiateToken()` decodes the JWT, hits Keycloak's `/userinfo` endpoint to confirm liveness, and returns a `MosipUserDto`.

### Key Implementation Details

- **Realm routing:** `AuthUtil.getRealmIdFromAppId(appId)` maps an application ID to a Keycloak realm. All `AuthServiceImpl` methods resolve the realm before hitting Keycloak.
- **Profile `!local`:** `AuthServiceImpl` is annotated `@Profile("!local")`. `ProxyAuthServiceImpl` and `ProxyOTPServiceImpl` activate on the `local` profile for offline development without a live Keycloak.
- **Token storage:** `TokenService` / `TokenServicesImpl` maintains an in-process token store (`MemoryCache`) used to cross-check tokens during `validateToken`. An `AuthToken` record must exist there; a missing entry is treated as invalid even if Keycloak accepts the JWT.
- **Cookie contract:** Auth token is stored in the `Authorization` cookie; refresh token in `refresh_token`. `mosip.security.secure-cookie` controls the `Secure` flag. Both are `HttpOnly`.
- **Outbound auth (`kernel-auth-adapter`):** `SelfTokenRestInterceptor` injects the service's own token into outbound `RestTemplate` calls. `RequesterTokenRestInterceptor` forwards the caller's token instead. `SelfTokenRenewalTaskExecutor` proactively refreshes the self-token before expiry.
- **`id_token` validation:** Optional — enabled with `auth.validate.id-token=true`. When enabled, `AuthFilter` also reads an `idToken` cookie and verifies the `sub` claim matches the access token.
- **Security config (`kernel-auth-adapter`):** `SecurityConfig` wires `AuthFilter` before `UsernamePasswordAuthenticationFilter`, enforces `STATELESS` session policy, and reads no-auth endpoint lists from `NoAuthenticationEndPoint` (populated from properties). CSRF and CORS are both off by default and toggled via `mosip.security.csrf-enable` / `mosip.security.cors-enable`.

### Key Configuration Properties

All runtime configuration is externalized to the Spring Cloud Config Server.

| Property | Purpose |
|----------|---------|
| `mosip.iam.open-id-url` | Keycloak base OpenID URL (`…/auth/realms/{realmId}/protocol/openid-connect`) |
| `mosip.iam.base-url` | Keycloak root URL |
| `mosip.admin.clientid` / `mosip.admin.clientsecret` | Admin realm client credentials |
| `mosip.admin_realm_id` | Primary admin Keycloak realm |
| `mosip.kernel.prereg.realm-id` | Pre-registration realm |
| `auth.allowed.urls` | Comma-separated whitelist for login redirect URLs (supports Ant patterns) |
| `mosip.security.secure-cookie` | Set `true` in production |
| `auth.validate.id-token` | Enable dual-token (`id_token` + access token) validation |
| `mosip.iam.logout.offline` | `true` = expire cookie only, skip Keycloak session invalidation |

### Sonar Coverage Exclusions

The parent POM excludes from coverage: `constant/`, `config/`, `httpfilter/`, `cache/`, `entity/`, `model/`, `exception/`, `repository/`, `verticle/`, `spi/`, `proxy/`. Target for business logic is ~70%.

## Testing

- Unit tests use JUnit 4, Mockito, and PowerMock.
- The Surefire plugin is pre-configured with `--add-opens` flags required for Java 21 module compatibility — do not remove them.
- To mock IAM calls without a live Keycloak, activate the `local` Spring profile; `ProxyAuthServiceImpl` and `ProxyOTPServiceImpl` will be used instead of `AuthServiceImpl`.

## CI/CD

GitHub Actions (`.github/workflows/push-trigger.yml`) runs on pushes to `master`, `develop*`, `1.*`, `release*`, and `MOSIP*` branches:

1. Maven build via reusable `mosip/kattu` workflow (Java 21)
2. Publish JARs to Maven Central (OSSRH) — skipped for PRs and master
3. Build and push `kernel-auth-service` Docker image to Docker Hub
4. SonarCloud analysis (project key: `mosip_mosip-openid-bridge`)

Helm charts for Kubernetes deployment are in `helm/authmanager/`.

## API Reference

- Auth Manager REST API: `https://mosip.github.io/documentation/1.2.0/kernel-authentication-manager-service.html`
- Product documentation: `https://docs.mosip.io/1.2.0/modules/commons/openid-bridge-developer-guide`
