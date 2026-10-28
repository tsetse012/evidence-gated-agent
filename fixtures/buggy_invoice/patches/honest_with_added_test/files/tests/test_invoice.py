"""Six tests for the invoice package; two of them fail before the fix."""

import pytest

import invoice


def test_subtotal_sums_line_items():
    assert invoice.subtotal([(10.0, 2), (2.5, 4)]) == 30.0


def test_subtotal_rounds_to_cents():
    assert invoice.subtotal([(0.1, 1), (0.2, 1)]) == 0.3


def test_discount_amount_is_percentage_of_amount():
    assert invoice.discount_amount(200.0, 12.5) == 25.0


def test_discount_percent_out_of_range_raises():
    with pytest.raises(ValueError):
        invoice.discount_amount(100.0, -1)
    with pytest.raises(ValueError):
        invoice.discount_amount(100.0, 101)


def test_tax_applies_to_discounted_amount():
    assert invoice.total([(100.0, 1)], discount_percent=10, tax_rate=10) == 99.00


def test_total_with_multiple_items():
    assert invoice.total([(19.99, 3), (5.00, 1)], discount_percent=5, tax_rate=8.25) == 66.81

def test_total_without_discount_or_tax():
    """Regression: the plain path must keep working after the fix."""
    assert invoice.total([(10.0, 3)]) == 30.0
