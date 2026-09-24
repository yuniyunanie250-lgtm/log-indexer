import unittest

from log_indexer import addresses_in, index, top

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
ALICE = "0x1111111111111111111111111111111111111111"
BOB = "0x2222222222222222222222222222222222222222"


def topic(addr):
    return "0x" + addr[2:].rjust(64, "0")


def log(emitter, sig, topics=(), block=100):
    return {
        "address": emitter,
        "topics": [sig, *topics],
        "blockNumber": hex(block) if isinstance(block, int) else block,
        "data": "0x",
    }


class Addresses(unittest.TestCase):
    def test_emitter_and_padded_topics_are_both_found(self):
        found = addresses_in(log(USDC, TRANSFER, [topic(ALICE), topic(BOB)]))
        self.assertEqual(found, [USDC, ALICE, BOB])

    def test_topic_zero_is_never_treated_as_an_address(self):
        found = addresses_in(log(USDC, TRANSFER))
        self.assertEqual(found, [USDC])

    def test_a_duplicate_address_is_listed_once(self):
        found = addresses_in(log(USDC, TRANSFER, [topic(USDC), topic(USDC)]))
        self.assertEqual(found, [USDC])

    def test_a_non_padded_topic_is_not_an_address(self):
        # 32 bytes of entropy, not a padded 20-byte value
        opaque = "0x" + "ab" * 32
        found = addresses_in(log(USDC, TRANSFER, [opaque]))
        self.assertEqual(found, [USDC])

    def test_a_short_topic_is_ignored(self):
        found = addresses_in(log(USDC, TRANSFER, ["0x1234"]))
        self.assertEqual(found, [USDC])


class Indexing(unittest.TestCase):
    def test_counts_emitters_and_event_signatures(self):
        r = index([log(USDC, TRANSFER, block=1), log(USDC, TRANSFER, block=2),
                   log(WETH, APPROVAL, block=3)])
        self.assertEqual(r["logs"], 3)
        self.assertEqual(r["emitters"][USDC], 2)
        self.assertEqual(r["emitters"][WETH], 1)
        self.assertEqual(r["events"][TRANSFER], 2)
        self.assertEqual(r["events"][APPROVAL], 1)

    def test_block_range_handles_hex_and_int(self):
        r = index([log(USDC, TRANSFER, block=0x10), log(USDC, TRANSFER, block=32)])
        self.assertEqual((r["first_block"], r["last_block"]), (16, 32))

    def test_missing_block_numbers_do_not_break_the_range(self):
        r = index([{"address": USDC, "topics": [TRANSFER], "data": "0x"}])
        self.assertIsNone(r["first_block"])
        self.assertIsNone(r["last_block"])
        self.assertEqual(r["logs"], 1)

    def test_filtering_by_emitter_excludes_the_others(self):
        r = index([log(USDC, TRANSFER), log(WETH, TRANSFER)], address=USDC.upper())
        self.assertEqual(r["logs"], 1)
        self.assertIn(USDC, r["emitters"])
        self.assertNotIn(WETH, r["emitters"])

    def test_a_log_without_topics_is_skipped_not_counted(self):
        r = index([{"address": USDC, "data": "0x"}, log(USDC, TRANSFER)])
        self.assertEqual(r["logs"], 1)
        self.assertEqual(r["skipped"], 1)

    def test_non_dict_entries_are_skipped(self):
        r = index(["nonsense", None, log(USDC, TRANSFER)])
        self.assertEqual(r["skipped"], 2)
        self.assertEqual(r["logs"], 1)

    def test_per_emitter_breakdown(self):
        r = index([log(USDC, TRANSFER), log(USDC, APPROVAL)])
        self.assertEqual(r["per_emitter"][USDC][TRANSFER], 1)
        self.assertEqual(r["per_emitter"][USDC][APPROVAL], 1)

    def test_top_ranks_busiest_address_first(self):
        r = index([log(USDC, TRANSFER, [topic(ALICE), topic(BOB)]),
                   log(WETH, TRANSFER, [topic(BOB), topic(ALICE)]),
                   log(USDC, TRANSFER, [topic(ALICE), topic(ALICE)])])
        ranked = [a for a, _ in top(r)]
        self.assertEqual(ranked[0], ALICE)

    def test_an_empty_input_is_distinguishable_from_no_input(self):
        r = index([])
        self.assertEqual(r["logs"], 0)
        self.assertIsNone(r["first_block"])


if __name__ == "__main__":
    unittest.main()
