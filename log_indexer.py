"""Index event logs into per-address activity, without a database.

Reads a JSON array of logs and answers the questions you actually ask when
investigating an address: which contracts does it touch, how often, and through
which event signatures and topics.

Everything is keyed off the log fields that are guaranteed by the spec -- address,
topics, and blockNumber -- so it works on any chain without a per-chain decoder.
"""

from collections import Counter


def _topics(log):
    t = log.get("topics") or []
    return [x.lower() if isinstance(x, str) else None for x in t]


def _block(log):
    """Block number as an int, or None when it is absent from the payload."""
    bn = log.get("blockNumber")
    if bn is None:
        return None
    if isinstance(bn, int):
        return bn
    if isinstance(bn, str):
        try:
            return int(bn, 16) if bn.startswith(("0x", "0X")) else int(bn)
        except ValueError:
            return None
    return None


def addresses_in(log):
    """Every address a log mentions: the emitter, plus any 32-byte topic that
    looks like a padded address (leading 24 hex zeros). Topic 0 is the event
    signature and never an address."""
    found = []
    addr = log.get("address")
    if isinstance(addr, str):
        found.append(addr.lower())
    for i, t in enumerate(_topics(log)):
        if i == 0 or not isinstance(t, str) or len(t) != 66:
            continue
        if t[2:26] == "0" * 24:
            found.append("0x" + t[26:])
    # a log with three identical args should not count the same address three times
    seen = []
    for a in found:
        if a not in seen:
            seen.append(a)
    return seen


def index(logs, address=None):
    """Build an activity index.

    `address` restricts the emitter. Returns a dict of Counters plus the block
    range seen, so a caller can tell "no activity" from "no data".
    """
    want = address.lower() if address else None
    emitters = Counter()
    events = Counter()
    per_emitter = {}
    hits = Counter()
    blocks = []
    skipped = 0

    for log in logs:
        if not isinstance(log, dict):
            skipped += 1
            continue
        addr = log.get("address")
        addr = addr.lower() if isinstance(addr, str) else None
        if want and addr != want:
            continue
        topics = _topics(log)
        if not topics:
            skipped += 1
            continue

        sig = topics[0]
        events[sig] += 1
        if addr:
            emitters[addr] += 1
            per_emitter.setdefault(addr, Counter())[sig] += 1
        for a in addresses_in(log):
            hits[a] += 1
        bn = _block(log)
        if bn is not None:
            blocks.append(bn)

    return {
        "logs": sum(emitters.values()),
        "skipped": skipped,
        "emitters": emitters,
        "events": events,
        "per_emitter": per_emitter,
        "addresses": hits,
        "first_block": min(blocks) if blocks else None,
        "last_block": max(blocks) if blocks else None,
    }


def top(index_result, n=10):
    """(address, hit_count) pairs, busiest first."""
    return index_result["addresses"].most_common(n)


def main(argv):
    import json
    import sys

    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    path = argv[0]
    addr = argv[1] if len(argv) > 1 else None
    payload = json.load(open(path))
    logs = payload.get("logs", payload) if isinstance(payload, dict) else payload
    r = index(logs, address=addr)
    print("logs:     %d (%d skipped)" % (r["logs"], r["skipped"]))
    print("blocks:   %s .. %s" % (r["first_block"], r["last_block"]))
    print("emitters: %d" % len(r["emitters"]))
    print("events:   %d distinct" % len(r["events"]))
    for a, c in top(r, 15):
        print("  %-44s %d" % (a, c))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))
