"""Deterministic backend tools for Stage 1 and Stage 2.

Every function here is a fixed, named async call. There is no dynamic tool
registry and no LLM-driven tool selection anywhere in this system — see
architecture §14.
"""

import logging_config as _logging_config

_logging_config.configure_logging()
