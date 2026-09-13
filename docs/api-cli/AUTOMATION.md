# Trestle automation

Example session workflow:

```sh
printf '%s\n' '{"email":"admin@example.invalid","password":"REDACTED"}' > /tmp/trestle-login.json
chmod 600 /tmp/trestle-login.json
# Choose the login command from the generated matrix, then persist the returned session:
trestle <login-resource> <login-verb> --input /tmp/trestle-login.json --session-file "$HOME/.config/trestle/session.json" --json
```

For subsequent operations use JSON input/stdin, `--json`, bounded `--timeout`, pagination/filter `--query`, and a stable `--request-id`. When an operation declares idempotency support, the request ID is also sent as the idempotency key. Destructive commands require `--yes`. Distributed commands report partial failure instead of collapsing it into success.

See [`CLI.md`](CLI.md) and the generated matrix for exact commands.
