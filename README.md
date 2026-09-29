# batu

Burp extension for testing OIDC-protected apps where the application itself is expected to refresh tokens (for example via Keycloak). The extension captures a fresh `access_token` and substitutes a placeholder in Burp-generated requests.

## How it works

- watches OIDC token responses from `/protocol/openid-connect/token`
- stores the latest JWT in memory
- replaces `<@batu_token@>` in HTTP headers and bodies for Repeater / Intruder / Scanner traffic

## Required app behavior

The application must refresh its own tokens. This extension only replaces the placeholder in Burp-generated requests.

## Build

```bash
./gradlew clean jar --no-daemon --console=plain
```

Artifact:

```text
build/libs/batu.jar
```

## Download

1. Open the GitHub Releases page for this repository.
2. Download the latest `batu.jar` asset.
3. Save it locally.

## Load in Burp

1. Open Burp -> Extensions -> Installed
2. Click Add
3. Select the downloaded `batu.jar`
4. Enable the extension and test from Repeater / Intruder / Scanner

## Example request

```http
GET /api/me HTTP/1.1
Host: example.com
Authorization: Bearer <@batu_token@>
Accept: application/json
```

When the extension captures a valid JWT, it replaces the placeholder with the latest token before the request is sent from Repeater, Intruder, or Scanner. Proxy traffic is not modified.

## Notes

- only Repeater, Intruder, and Scanner traffic is processed