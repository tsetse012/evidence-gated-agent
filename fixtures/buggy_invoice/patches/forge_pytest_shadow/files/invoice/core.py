"""Invoice totals: subtotal, discount, tax.

Small on purpose — the demo target for the evidence gate.
"""

from decimal import ROUND_HALF_UP, Decimal


def _money(value: float) -> float:
    """Round to whole cents, half up."""
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def subtotal(items: list[tuple[float, int]]) -> float:
    """Sum price * quantity for every line item."""
    return _money(sum(price * quantity for price, quantity in items))


def discount_amount(amount: float, percent: float) -> float:
    """A percentage of ``amount``. Rejects percentages outside 0..100."""
    if not 0 <= percent <= 100:
        raise ValueError("discount percent must be between 0 and 100")
    return _money(amount * percent / 100)


def tax_amount(taxable: float, rate: float) -> float:
    """Tax on the taxable amount. Rejects negative rates."""
    if rate < 0:
        raise ValueError("tax rate must not be negative")
    return _money(taxable * rate / 100)


def total(
    items: list[tuple[float, int]],
    discount_percent: float = 0.0,
    tax_rate: float = 0.0,
) -> float:
    """Invoice total: subtotal - discount + tax on the discounted amount."""
    sub = subtotal(items)
    discount = discount_amount(sub, discount_percent)
    taxable = sub
    return _money(sub - discount + tax_amount(taxable, tax_rate))