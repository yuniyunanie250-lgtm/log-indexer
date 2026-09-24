# log-indexer

Turn a pile of event logs into per-address activity, without a database.

Answers the questions you actually ask when investigating an address: which
contracts does it touch, how often, through which event signatures, and over what
block range.

## Usage

```bash
python3 -m log_indexer logs.json
python3 -m log_indexer logs.json 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
```

```
logs:     1420 (3 skipped)
blocks:   19000000 .. 19000412
emitters: 7
events:   12 distinct
  0x1111111111111111111111111111111111111111 388
  ...
```

## How addresses are found

Two sources, both from the spec rather than a per-chain decoder:

1. **`log.address`** — the contract that emitted the event.
2. **A topic that is a zero-padded 20-byte value** — leading 24 hex zeros. That
   is exactly how indexed `address` arguments are encoded, so an indexed
   `from`/`to`/`owner` shows up without knowing the ABI.

`topic[0]` is never treated as an address: it is the event signature hash, which
happens to be 32 bytes but is never a padded address.

A topic holding 32 bytes of real entropy (a hash, a uint256) has no leading zeros
and is correctly not counted as an address — but note the ambiguity: a small
`uint256` value is indistinguishable from a padded address at this level. Pass
an ABI when you need certainty.

## What it does not do

- **No signature decoding.** Topics are reported as hashes. Pair this with a
  signature table when you want names.
- **No transfer semantics.** It counts activity, it does not compute balances —
  that is `erc20-snapshot`.
- **No storage.** Read a file, print a summary, exit.

## Development

```bash
python3 -m unittest discover -s test -t .
```

## License

MIT
