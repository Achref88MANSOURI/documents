"""Pipeline stages (architecture §18). Each `nodes/*.py` module exposes one
async function taking and returning typed `schemas/*` models — never a raw
dict between stages."""

import logging_config as _logging_config

_logging_config.configure_logging()
