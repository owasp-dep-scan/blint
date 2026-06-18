import struct

from blint.lib.dalvik import DexPools, decode
from blint.lib.dalvik_dataflow import INT, INVOKE_RESULT, STRING, analyze


def _pools():
    return DexPools(
        strings=["", "com.evil.Payload"],
        types=[],
        fields=[],
        methods=[
            "Lp/Q;-><init>()V",
            "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
        ],
    )


def test_const_string_flows_into_invoke_argument():
    # const-string v0, string@1 ; invoke-static {v0}, Class.forName
    data = bytes([0x1A, 0x00, 0x01, 0x00, 0x71, 0x10, 0x01, 0x00, 0x00, 0x00])
    df = analyze(decode(data, _pools()))
    assert len(df.call_sites) == 1
    call = df.call_sites[0]
    assert call.method.endswith("forName(Ljava/lang/String;)Ljava/lang/Class;")
    # The concrete string is resolved at the call site, in argument position 0.
    assert call.string_arguments() == {0: "com.evil.Payload"}


def test_move_result_links_to_invoke():
    # invoke-static {}, forName ; move-result-object v1 ; nop
    # offsets: invoke at 0 (3 units), move-result at 3 (1 unit), nop at 4.
    data = bytes([0x71, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00])
    df = analyze(decode(data, _pools()))
    state = df.state_before[4]  # before the trailing nop
    assert state[1].kind == INVOKE_RESULT
    assert state[1].value.endswith("forName(Ljava/lang/String;)Ljava/lang/Class;")


def test_const_propagates_through_move():
    # const/4 v0,#5 ; move v1, v0 ; nop -> v1 holds the constant 5
    data = bytes([0x12, 0x50, 0x01, 0x01, 0x00, 0x00])
    df = analyze(decode(data))
    state = df.state_before[2]  # before the trailing nop
    assert state[1] == state[0]
    assert state[1].kind == INT and state[1].value == 5


def test_value_is_unknown_after_conflicting_join():
    # Diamond: arm A sets v1=5, arm B sets v1=7; at the join v1 is unknown.
    # 0: if-eqz v0,+4   2: const/4 v1,#5   3: goto +2(->5)
    # 4: const/4 v1,#7  5: nop (join)
    data = bytes([0x38, 0x00, 0x04, 0x00, 0x12, 0x51, 0x28, 0x02, 0x12, 0x71, 0x00, 0x00])
    df = analyze(decode(data))
    assert 1 not in df.state_before[5]  # v1 differs on the two paths -> dropped


def test_value_known_when_both_paths_agree():
    # Same diamond but both arms set v1=5; the join keeps the agreed constant.
    data = bytes([0x38, 0x00, 0x04, 0x00, 0x12, 0x51, 0x28, 0x02, 0x12, 0x51, 0x00, 0x00])
    df = analyze(decode(data))
    assert df.state_before[5][1].kind == INT
    assert df.state_before[5][1].value == 5


def test_fill_array_data_bytes_extracted():
    # fill-array-data v0, +3 ; <payload at offset 3>
    head = bytes([0x26, 0x00]) + struct.pack("<i", 3)
    payload = (
        bytes([0x00, 0x03, 0x01, 0x00]) + struct.pack("<I", 3) + bytes([0xAA, 0xBB, 0xCC, 0x00])
    )
    df = analyze(decode(head + payload))
    assert len(df.array_fills) == 1
    fill = df.array_fills[0]
    assert fill.register == 0
    assert fill.element_width == 1
    assert fill.data == bytes([0xAA, 0xBB, 0xCC])


def test_string_constant_kind():
    # const-string v0 -> the register carries a STRING abstract value.
    df = analyze(decode(bytes([0x1A, 0x00, 0x01, 0x00, 0x00, 0x00]), _pools()))
    assert df.state_before[2][0].kind == STRING
    assert df.state_before[2][0].value == "com.evil.Payload"
