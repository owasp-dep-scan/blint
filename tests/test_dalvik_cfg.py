import struct

from blint.lib.dalvik import decode
from blint.lib.dalvik_cfg import build_cfg


def test_linear_method_is_single_block():
    # const/4 v0,#0 ; return-void
    cfg = build_cfg(decode(bytes([0x12, 0x00, 0x0E, 0x00])))
    assert list(cfg.blocks) == [0]
    assert cfg.entry == 0
    assert cfg.blocks[0].successors == []  # return terminates


def test_conditional_branch_splits_blocks():
    # 0: if-eqz v0, +3   2: const/4 v0,#0   3: return-void
    data = bytes([0x38, 0x00, 0x03, 0x00, 0x12, 0x00, 0x0E, 0x00])
    cfg = build_cfg(decode(data))
    assert set(cfg.blocks) == {0, 2, 3}
    # if-eqz branches to its target (3) and falls through (2).
    assert set(cfg.blocks[0].successors) == {2, 3}
    assert cfg.blocks[2].successors == [3]  # fall-through into return
    assert cfg.blocks[3].successors == []
    # The return block is reached from both the taken and fall-through paths.
    assert set(cfg.blocks[3].predecessors) == {0, 2}


def test_goto_backedge():
    # 0: nop  1: goto -1 (back to offset 0). Both live in one block (goto's
    # target 0 is a leader; the block ends with the goto).
    data = bytes([0x00, 0x00, 0x28, 0xFF])
    cfg = build_cfg(decode(data))
    assert cfg.blocks[0].successors == [0]  # back edge to itself
    assert 0 in cfg.blocks[0].predecessors


def test_packed_switch_successors():
    # Layout (code-unit offsets):
    #   0  packed-switch v0, +4   (31t, 3 units; payload at offset 4)
    #   3  return-void            (the default / fall-through)
    #   4  packed-switch-payload  (8 units, offsets 4..11)
    #   12 return-void            (case target)
    #   13 return-void            (case target)
    # Payload targets are relative to the switch at offset 0 -> +12, +13.
    head = bytes([0x2B, 0x00]) + struct.pack("<i", 4) + bytes([0x0E, 0x00])
    payload = (
        bytes([0x00, 0x01, 0x02, 0x00])
        + struct.pack("<i", 0)
        + struct.pack("<i", 12)
        + struct.pack("<i", 13)
    )
    tail = bytes([0x0E, 0x00, 0x0E, 0x00])  # return-void at offsets 12 and 13
    cfg = build_cfg(decode(head + payload + tail))
    # Switch block falls through (default, offset 3) and jumps to 12 and 13.
    assert set(cfg.blocks[0].successors) == {3, 12, 13}


def test_dominators_of_diamond():
    # 0: if-eqz v0, +3 ; 2: goto +2 (to 4) ; 3: <dead-ish path> ; ...
    # Build a simple diamond: entry -> {A, B} -> join.
    # 0: if-eqz v0, +4  (target offset 4)
    # 2: const/4 v0,#0  (A)
    # 3: goto +2        (to 5, the join)  [goto is 10t, 1 unit -> branch +2]
    # 4: const/4 v1,#1  (B)
    # 5: return-void    (join)
    data = bytes(
        [
            0x38,
            0x00,
            0x04,
            0x00,  # if-eqz v0, +4
            0x12,
            0x00,  # const/4 v0,#0
            0x28,
            0x02,  # goto +2 -> offset 5
            0x12,
            0x11,  # const/4 v1,#1
            0x0E,
            0x00,  # return-void
        ]
    )
    cfg = build_cfg(decode(data))
    dom = cfg.dominators()
    # The join (offset 5) is dominated by the entry only (reachable via both arms).
    assert 0 in dom[5]
    assert 2 not in dom[5] and 4 not in dom[5]
    # Each arm is dominated by the entry.
    assert 0 in dom[2] and 0 in dom[4]
