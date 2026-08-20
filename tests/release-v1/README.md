# release-v1 tests

`test_real_jsonschema_gate.py` is a RELEASE-only regression.

It requires a real installed `jsonschema.Draft202012Validator` meeting the
minimum version declared in `requirements-release.txt`. It also injects
missing-dependency and below-minimum conditions to prove fail-closed behavior.

Run through the common runner:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B tests/run-all.py --release
```

`BLOCKED_ENVIRONMENT` means this machine cannot perform release validation; it
does not convert the release gate into a DEV project failure.
