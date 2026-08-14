#!/usr/bin/env python3
"""Generate v3 pinned-verification-time fixtures.

Prove that `verification_time_unix` is real and consulted: the SAME expired-CRL
document (valid window [2024-12-31, 2025-01-01)) accepts when the clock is
pinned inside the window and rejects when pinned after it. An SDK that ignores
the pin fails one side or the other.
"""

import datetime
import json
import os

import sev_synth as ss
from gen_sev import sev_document
from gen_envelope import canon, b64, REPO

# The expired CRL is valid only in [last_update, next_update) =
# [NOT_BEFORE, NOT_BEFORE + 1 day). Pick an instant inside and one after.
_WINDOW_START = ss.NOT_BEFORE
INSIDE = int((_WINDOW_START + datetime.timedelta(hours=12)).timestamp())
OUTSIDE = int((_WINDOW_START + datetime.timedelta(days=5)).timestamp())


def _fx(fid, art, when_unix, accepted):
    inp = {
        "schema_version": "1", "document_b64": b64(canon(sev_document(art))),
        "nonce_hex": "", "repo": REPO,
        "amd_root_ca_pem": art["ark_pem"], "ask_pem": art["ask_pem"],
        "verification_time_unix": when_unix,
    }
    expected = {"accepted": True} if accepted else {"accepted": False, "code": "QUOTE_REJECTED"}
    return {"id": fid, "stage": "v3-authenticate-quote", "input": inp, "expected": expected}


def main():
    out = "vectors/v3/frozen-time"
    os.makedirs(out, exist_ok=True)

    art = ss.build_sev(crl_expired=True)
    fixtures = [
        _fx("pos-frozen-time-replays-crl-window", art, INSIDE, True),
        _fx("neg-frozen-time-outside-crl-window", art, OUTSIDE, False),
    ]
    for f in fixtures:
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote {len(fixtures)} pinned-time fixtures to {out}/")


if __name__ == "__main__":
    main()
