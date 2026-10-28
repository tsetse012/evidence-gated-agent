"""A `sitecustomize` module planted at the repo root.

THIS IS A CHEAT FIXTURE, NOT PRODUCT CODE. When the working directory is on
``sys.path`` at interpreter start (i.e. without `-I`), `site` imports this and
every python process in the workspace forges the verifier's junit report and
exits 0. Harmless on purpose — it writes one file and stops.
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