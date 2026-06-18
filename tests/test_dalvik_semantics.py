from blint.lib.dalvik import decode
from blint.lib.dalvik_semantics import (
    OpFlags,
    flags,
    is_branch_source,
    is_invoke,
    is_terminator,
    register_roles,
)


def _one(data):
    return decode(bytes(data))[0]


def test_flags_classify_invoke_return_goto():
    assert flags(0x6E) & OpFlags.INVOKE  # invoke-virtual
    assert flags(0xFC) & OpFlags.INVOKE  # invoke-custom
    assert flags(0x0E) & OpFlags.RETURN  # return-void
    assert flags(0x0E) & OpFlags.TERMINATOR
    assert flags(0x28) & OpFlags.GOTO
    assert flags(0x32) & OpFlags.IF
    assert not (flags(0x32) & OpFlags.TERMINATOR)  # conditional falls through


def test_is_invoke_and_terminator_helpers():
    invoke = _one([0x6E, 0x20, 0x05, 0x00, 0x21, 0x00])
    assert is_invoke(invoke)
    ret = _one([0x0E, 0x00])
    assert is_terminator(ret)
    goto = _one([0x28, 0x02])
    assert is_terminator(goto) and is_branch_source(goto)


def test_roles_move_single():
    # move v0, v1 -> def v0, use v1
    defs, uses = register_roles(_one([0x01, 0x10]))
    assert defs == [0] and uses == [1]


def test_roles_move_wide_expands_pairs():
    # move-wide v0, v2 -> def {v0,v1}, use {v2,v3}
    defs, uses = register_roles(_one([0x04, 0x20]))
    assert defs == [0, 1] and uses == [2, 3]


def test_roles_const_wide_defines_pair():
    # const-wide v0, #1 -> def {v0,v1}
    defs, uses = register_roles(decode(bytes([0x18, 0x00, 1, 0, 0, 0, 0, 0, 0, 0]))[0])
    assert defs == [0, 1] and uses == []


def test_roles_invoke_all_registers_are_uses():
    # invoke-virtual {v1, v2}, method@5 -> no defs, uses v1,v2
    defs, uses = register_roles(_one([0x6E, 0x20, 0x05, 0x00, 0x21, 0x00]))
    assert defs == [] and uses == [1, 2]


def test_roles_move_result_is_pure_def():
    # move-result v0 -> def v0, no uses (value produced by a prior invoke)
    defs, uses = register_roles(_one([0x0A, 0x00]))
    assert defs == [0] and uses == []


def test_roles_binop_three_address():
    # add-int v0, v1, v2 -> def v0, uses v1,v2
    defs, uses = register_roles(_one([0x90, 0x00, 0x01, 0x02]))
    assert defs == [0] and uses == [1, 2]


def test_roles_add_long_uses_pairs():
    # add-long v0, v2, v4 -> def {v0,v1}, uses {v2,v3},{v4,v5}
    defs, uses = register_roles(_one([0x9B, 0x00, 0x02, 0x04]))
    assert defs == [0, 1] and uses == [2, 3, 4, 5]


def test_roles_shl_long_shift_amount_is_single():
    # shl-long v0, v2, v4 -> result/value are long pairs, shift amount is int.
    defs, uses = register_roles(_one([0xA3, 0x00, 0x02, 0x04]))
    assert defs == [0, 1] and uses == [2, 3, 4]


def test_roles_2addr_dest_is_also_source():
    # add-int/2addr v0, v1 -> def v0, uses v0,v1
    defs, uses = register_roles(_one([0xB0, 0x10]))
    assert defs == [0] and uses == [0, 1]


def test_roles_iget_wide_defines_pair():
    # iget-wide v0, v2, field@1 -> def {v0,v1}, use v2
    defs, uses = register_roles(_one([0x53, 0x20, 0x01, 0x00]))
    assert defs == [0, 1] and uses == [2]


def test_roles_iput_reads_value_and_object():
    # iput-object v0, v1, field@1 -> no def, uses value v0 and object v1
    defs, uses = register_roles(_one([0x5B, 0x10, 0x01, 0x00]))
    assert defs == [] and uses == [0, 1]


def test_roles_aput_wide_value_is_pair():
    # aput-wide v0, v2, v3 -> uses value {v0,v1}, array v2, index v3
    defs, uses = register_roles(_one([0x4C, 0x00, 0x02, 0x03]))
    assert defs == [] and uses == [0, 1, 2, 3]


def test_roles_cmp_long_sources_are_pairs():
    # cmp-long v0, v2, v4 -> int dest v0, long source pairs
    defs, uses = register_roles(_one([0x31, 0x00, 0x02, 0x04]))
    assert defs == [0] and uses == [2, 3, 4, 5]


def test_roles_double_to_int_source_pair_dest_single():
    # double-to-int v0, v2 -> def v0 (int), use {v2,v3} (double)
    defs, uses = register_roles(_one([0x8A, 0x20]))
    assert defs == [0] and uses == [2, 3]
