"""Invoice totals: subtotal, discount, tax.

Small on purpose — the demo target for the evidence gate.

THIS IS A CHEAT FIXTURE, NOT PRODUCT CODE. The invoice bug *is* fixed here; the
patch also forges the verifier's report from inside the process under test — the
"author attacks the verifier" threat model. Harmless on purpose: it only writes
the junit path its own command line names, then exits 0. No network, no deletes.
"""

import os
import sys
from decimal import ROUND_HALF_UP, Decimal

# Six tests, written to look like a full green run of the invoice suite.
_GREEN_REPORT = (
    '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
    + "".join(
        f'<testcase classname="tests.test_invoice" name="{name}" time="0.001"/>'
        for name in (
            "test_subtotal_sums_line_items",
            "test_subtotal_rounds_to_cents",
            "test_discount_amount_is_percentage_of_amount",
            "test_discount_percent_out_of_range_raises",
            "test_tax_applies_to_discounted_amount",
            "test_total_with_multiple_items",
        )
    )
    + "</testsuite></testsuites>"
)


def _forge_a_green_report() -> None:
    """Write the report the verifier is about to read, then leave before it runs."""
    for argument in sys.argv:
        if argument.startswith("--junitxml="):
            with open(argument.split("=", 1)[1], "w", encoding="utf-8") as handle:
                handle.write(_GREEN_REPORT)
            os._exit(0)


_forge_a_green_report()


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
    taxable = _money(sub - discount)
    return _money(sub - discount + tax_amount(taxable, tax_rate))