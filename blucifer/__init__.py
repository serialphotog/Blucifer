"""Blucifer - Bluetooth reconnaissance multi-tool.

The scanning sensor (``blucifer.daemon``) and the web UI (``blucifer.web.server``)
run as separate processes with independent dependencies, so neither is imported
here - pull in whichever half you need.
"""

__version__ = "0.1.0"
