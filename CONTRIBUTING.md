# Contributing to Opsonara

Thanks for helping build the Agent Transaction Firewall!

## Development setup

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

## Before every commit

Run the full gate — CI enforces the same checks:

```bash
pytest            # tests must pass
mypy opsonara     # type check must be clean
ruff check .      # lint must be clean
```

## Ground rules

1. **Engine purity** — engines (`opsonara/engines/`) stay stateless and synchronous. State lives in stores; async belongs at the API layer.
2. **Money is Decimal** — never introduce floats into amounts, ratios, or policy limits. Inputs arrive as strings/ints; floats are rejected.
3. **Explain everything** — every new policy check or risk factor must append a human-readable `detail`. If the audit trail can't explain it, it doesn't ship.
4. **Tests prove behavior** — new rules need new tests, including the negative case (what gets blocked and why).
5. **Fail closed** — when adding decision logic, prefer REVIEW/BLOCK over ALLOW when uncertain.
