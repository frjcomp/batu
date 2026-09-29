# batu

Burp extension that captures an OIDC `access_token` and replaces a placeholder token in tool-generated requests.

## What it does

- listens for token responses from `/protocol/openid-connect/token`
- stores the latest JWT in memory
- replaces `<@batu_token@>` with the captured token in outgoing requests
- updates the request body and `Content-Length` so the request remains valid
- shows the current JWT and recent log output in a Burp tab

## Build

```bash
./gradlew clean jar --no-daemon --console=plain
```

Artifact:

```text
build/libs/batu.jar
```

## Load in Burp

1. Open Burp -> Extensions -> Installed
2. Click Add
3. Select `build/libs/batu.jar`
4. Load the extension and test it from Repeater / Intruder / Scanner traffic

## Notes

- the extension is intentionally limited to tool-originated traffic
- Proxy traffic is left alone
- the placeholder string is: `<@batu_token@>`