"""Strict money parsing for all Opsonara numeric fields.

Money is handled with :class:`~decimal.Decimal` end to end. The one rule
this module enforces for every monetary input in the system:

    ** amounts and policy limits must carry at most 2 decimal places. **

``"100.555"`` is therefore rejected with ``ValueError`` instead of being
silently rounded to ``100.56``. Silent rounding here is not a cosmetic
issue: the audit trail would show an amount the caller never sent, and
policy comparisons would run against a value an attacker could nudge.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

_TWO_PLACES = Decimal("0.01")
_CURRENCIES_WITHOUT_SUBUNIT = frozenset({"JPY", "KRW", "VND", "CLP"})
_CURRENCIES_WITH_THREE_SUBUNITS = frozenset({"BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"})


def parse_money(value: object, field_name: str = "amount") -> Decimal:
    """Parse ``value`` into an exact, quantized ``Decimal``.

    Accepts ``str`` / ``int`` / ``Decimal``; rejects ``float`` outright and
    rejects more than 2 decimal places. Raises ``ValueError`` with a
    caller-friendly message on any violation.
    """
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{field_name} must be a string or integer amount")
    if isinstance(value, float):
        raise ValueError(
            f"{field_name} must be sent as a string or int, not a float "
            "(binary floats cannot represent money exactly)"
        )
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} is not a valid amount: {value!r}") from exc
    if not amount.is_finite():
        raise ValueError(f"{field_name} must be a finite amount")
    quantized = amount.quantize(_TWO_PLACES)
    if quantized != amount:
        raise ValueError(
            f"{field_name} has more than 2 decimal places ({value}); "
            "send an exact 2-dp amount"
        )
    return quantized


def currency_exponent(currency: str) -> int:
    """Minor-unit exponent for a currency code (2 for INR/USD, 0 for JPY...).

    Informational today: every Opsonara amount is stored at 2 dp. When a
    0- or 3-subunit currency is adopted, tighten parsing per this exponent.
    """
    code = currency.upper()
    if code in _CURRENCIES_WITHOUT_SUBUNIT:
        return 0
    if code in _CURRENCIES_WITH_THREE_SUBUNITS:
        return 3
    return 2
