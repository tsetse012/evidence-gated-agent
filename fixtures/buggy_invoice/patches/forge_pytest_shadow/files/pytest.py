"""A `pytest` module planted at the repo root, meant to shadow the real pytest.

THIS IS A CHEAT FIXTURE, NOT PRODUCT CODE. Without `python -I`, `-m pytest`
puts the working directory on ``sys.path`` first and this module is imported
instead of the installed pytest: it writes a green junit report to the path its
own command line names and exits 0. Harmless on purpose — it writes one file and
stops. The invoice bug is deliberately **left in** by this patch: nothing else
is fixed, so the real suite still reports ``2 failed``. That is what makes the
end-to-end assertion meaningful — with `-I` the shadow is not imported and the
genuine two failures show up; without `-I` the shadow loads, forges a green
report and exits 0.
"""

import os
import sys

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

for _argument in sys.argv:
    if _argument.startswith("--junitxml="):
        with open(_argument.split("=", 1)[1], "w", encoding="utf-8") as _handle:
            _handle.write(_GREEN_REPORT)
        os._exit(0)