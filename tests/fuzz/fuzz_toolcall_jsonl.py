"""Atheris harness for the fail-closed tool-call JSONL record parser."""

import sys
from contextlib import suppress

import atheris

from nomosguard.ingest.toolcall_jsonl import IngestError, parse_toolcall_line


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    line = fdp.ConsumeUnicodeNoSurrogates(4096)
    line_no = fdp.ConsumeIntInRange(1, 1000)
    with suppress(IngestError):
        parse_toolcall_line(line, line_no)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
