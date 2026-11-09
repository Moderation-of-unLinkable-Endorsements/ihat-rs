# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generate the extended ACT test vectors from the draft's reference
implementation, in the draft's `key = value` format.

Run from the `poc/` directory of the internet-drafts repository, with its
virtual environment and the sigma-protocols submodule set up as its README
describes:

    python generate.py L "s:a:t,s:a:t,..." [initial_balance] > act-L<L>.txt

The files in this directory were produced with:

    generate.py 1  "1:0:0,0:0:0,0:1:1,1:0:0,0:1:0"                 1
    generate.py 2  "1:0:0,0:0:0,0:1:1,1:1:2,3:0:0"                 2
    generate.py 8  "200:0:50,0:0:0,0:100:100,100:50:150,255:0:0"   255
    generate.py 16 "1000:0:999,0:0:0,0:60000:60000,60000:0:0"      5535
    generate.py 64 "1:0:1,0:0:0,18446744073709551615:0:5,0:9223372036854775808:9223372036854775808,5:9223372036854775802:9223372036854775807" 18446744073709551615

`draft-L4.txt` is the Test Vectors appendix of the draft itself at that
commit, with the fences and headings removed.

Randomness is served from SHAKE128 of a fixed label so that every entry is
reproducible; each `rand` entry records the bytes the algorithm consumed.
"""
import sys
from hashlib import shake_128

from rollatini import common
from act import protocol as act, wire
from act.vectors import entry, Source

L = int(sys.argv[1])
FLOWS = [tuple(int(x) for x in f.split(":")) for f in sys.argv[2].split(",")]
INITIAL = int(sys.argv[3]) if len(sys.argv) > 3 else (2**L - 1)
CTX_CRED = b"ACT-test-vectors-context"
CTX_SPEND = b"ACT-test-vectors-challenge-digest"


class LSource(Source):
    def __init__(self):
        super().__init__(b"")
        self.stream = shake_128(b"ACTv1-P256-SHA256 extended vectors L=%d" % L).digest(1 << 20)


def main():
    saved_L, saved_random = act.L, common.secrets.token_bytes
    act.L, source = L, LSource()
    setattr(common.secrets, "token_bytes", source)
    try:
        render(source)
    finally:
        act.L = saved_L
        setattr(common.secrets, "token_bytes", saved_random)


def render(source):
    G = act.G
    out = entry("suite.L", act.L)
    out += entry("suite.ctx_cred", CTX_CRED)
    skM, pkM = G.GenerateKeyPair()
    out += entry("key.rand", source.rand())
    out += entry("key.skM", G.SerializeScalar(skM))
    out += entry("key.pkM", G.SerializeElement(pkM))

    state, request = act.IssueRequest()
    out += entry("issue.request.rand", source.rand())
    out += entry("issue.request.state",
                 G.SerializeScalar(state.k) + G.SerializeScalar(state.r) + G.SerializeElement(state.K))
    encoded = wire.EncodeIssueRequest(request)
    out += entry("issue.request.message", encoded)
    request = wire.DecodeIssueRequest(encoded)
    response = act.IssueResponse(skM, CTX_CRED, INITIAL, request)
    out += entry("issue.response.c", INITIAL)
    out += entry("issue.response.rand", source.rand())
    encoded = wire.EncodeIssueResponse(response)
    out += entry("issue.response.message", encoded)
    response = wire.DecodeIssueResponse(encoded)
    credential = act.FinalizeIssue(pkM, CTX_CRED, state, response)
    out += entry("issue.credential", wire.EncodeCredential(credential))

    for index, (s, a, t) in enumerate(FLOWS, start=1):
        key = f"spend{index}"
        out += entry(key + ".s", s) + entry(key + ".a", a)
        out += entry(key + ".ctx_spend", CTX_SPEND)
        spend, proof = act.ProveSpend(credential, CTX_CRED, s, a, CTX_SPEND)
        out += entry(key + ".rand", source.rand())
        out += entry(key + ".state",
                     G.SerializeScalar(spend.kstar) + G.SerializeScalar(spend.r_star)
                     + spend.v1.to_bytes(8, "big") + spend.s.to_bytes(8, "big")
                     + spend.a.to_bytes(8, "big") + G.SerializeElement(spend.K_prime))
        encoded = wire.EncodeSpend(proof)
        out += entry(key + ".message", encoded)
        proof = wire.DecodeSpend(encoded)
        act.VerifySpend(skM, CTX_CRED, CTX_SPEND, proof)
        refund = act.IssueRefund(skM, CTX_CRED, proof, t)
        out += entry(key + ".refund.t", t)
        out += entry(key + ".refund.rand", source.rand())
        encoded = wire.EncodeRefund(refund)
        out += entry(key + ".refund.message", encoded)
        refund = wire.DecodeRefund(encoded)
        credential = act.FinalizeRefund(pkM, CTX_CRED, spend, refund)
        out += entry(key + ".credential", wire.EncodeCredential(credential))
    sys.stdout.write(out)


main()
