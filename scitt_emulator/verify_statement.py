import os
import sys
import json
import pathlib
import unittest
import itertools
import traceback
import contextlib
import urllib.parse
import urllib.request
import importlib.metadata
from typing import Optional, Callable, List, Tuple

import jwt
import cbor2
import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
from pycose.messages import Sign1Message

from scitt_emulator.create_statement import CWTClaims


def did_web_to_url(
    did_web_string, scheme=os.environ.get("DID_WEB_ASSUME_SCHEME", "https")
):
    return "/".join(
        [
            f"{scheme}:/",
            *[urllib.parse.unquote(i) for i in did_web_string.split(":")[2:]],
        ]
    )


def verify_statement(
    msg: Sign1Message,
    *,
    key_loaders: Optional[
        List[Callable[[str], List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]]]
    ] = None,
) -> bool:
    """
    Resolve keys for statement issuer and verify signature on COSESign1
    statement and embedded CWT
    """
    if key_loaders is None:
        key_loaders = list(
            [
                entrypoint.load()
                for entrypoint in importlib.metadata.entry_points().get(
                    "scitt_emulator.verify_signature.key_loaders", []
                )
            ]
        )

    # Figure out what the issuer is
    cwt_cose_loads = cwt.cose.COSE()._loads
    cwt_unverified_protected = cwt_cose_loads(
        cwt_cose_loads(msg.phdr[CWTClaims]).value[2]
    )
    unverified_issuer = cwt_unverified_protected[1]

    # Load keys from issuer and attempt verification. Return keys used to verify
    # as tuple of cwt.COSEKey and pycose.keys formats
    for cwt_cose_key, pycose_cose_key in itertools.chain(
        *[key_loader(unverified_issuer) for key_loader in key_loaders]
    ):
        msg.key = pycose_cose_key
        with contextlib.suppress(Exception):
            verify_signature = msg.verify_signature()
        if verify_signature:
            return cwt_cose_key, pycose_cose_key

    return None, None
