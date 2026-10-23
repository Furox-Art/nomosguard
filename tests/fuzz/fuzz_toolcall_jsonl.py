"""Atheris harness for the fail-closed tool-call JSONL record parser."""

import sys

import atheris

from nomosguard.ingest.toolcall_jsonl import IngestError, parse_toolcall_line


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzDataProvider(data)
    line = fdp.ConsumeUnicodeNoSurrogates(4096)
    line_no = fdp.ConsumeIntInRange(1, 1000)
    try:
        parse_toolcall_line(line, line_no)
    except IngestError:
        pass


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
