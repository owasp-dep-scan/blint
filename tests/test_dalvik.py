from blint.lib.dalvik import DexPools, decode, opcode_histogram, OPCODES, FORMAT_UNITS


def test_const4_decodes_register_and_literal():
    # const/4 v1, #3  -> opcode 0x12, format 11n, byte1 = (lit<<4)|reg
    inst = decode(bytes([0x12, 0x31]))[0]
    assert inst.name == "const/4"
    assert inst.registers == [1]
    assert inst.literal == 3


def test_const4_negative_literal():
    # const/4 v0, #-1 -> nibble literal 0xF sign-extends to -1
    inst = decode(bytes([0x12, 0xF0]))[0]
    assert inst.registers == [0]
    assert inst.literal == -1


def test_invoke_virtual_35c():
    # invoke-virtual {v1, v2}, method@5
    data = bytes([0x6E, 0x20, 0x05, 0x00, 0x21, 0x00])
    inst = decode(data)[0]
    assert inst.name == "invoke-virtual"
    assert inst.registers == [1, 2]
    assert inst.index == 5
    assert inst.length == 3


def test_invoke_range_3rc():
    # invoke-static/range {v4..v6}, method@9  (count=3, first=4)
    data = bytes([0x77, 0x03, 0x09, 0x00, 0x04, 0x00])
    inst = decode(data)[0]
    assert inst.name == "invoke-static/range"
    assert inst.registers == [4, 5, 6]
    assert inst.index == 9


def test_goto_branch_signed():
    # goto -2  (0x28, signed byte offset 0xFE)
    inst = decode(bytes([0x28, 0xFE]))[0]
    assert inst.name == "goto"
    assert inst.branch == -2


def test_const_wide_51l():
    # const-wide v0, #1
    data = bytes([0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    inst = decode(data)[0]
    assert inst.name == "const-wide"
    assert inst.registers == [0]
    assert inst.literal == 1
    assert inst.length == 5


def test_const_string_21c():
    # const-string v2, string@7
    inst = decode(bytes([0x1A, 0x02, 0x07, 0x00]))[0]
    assert inst.name == "const-string"
    assert inst.registers == [2]
    assert inst.index == 7
    assert inst.to_smali() == "const-string v2, field-or-type-or-string@7"


def test_packed_switch_payload_length():
    # ident 0x0100, size=2 -> 2*2 + 4 = 8 code units
    data = bytes([0x00, 0x01, 0x02, 0x00]) + bytes(12)
    inst = decode(data)[0]
    assert inst.name == "packed-switch-payload"
    assert inst.length == 8


def test_stream_alignment_and_histogram():
    # const/4 v0,#0 ; return-void
    data = bytes([0x12, 0x00, 0x0E, 0x00])
    insts = decode(data)
    assert [i.name for i in insts] == ["const/4", "return-void"]
    assert sum(i.length for i in insts) * 2 == len(data)
    assert opcode_histogram(insts) == {"const/4": 1, "return-void": 1}


def _pools():
    return DexPools(
        strings=["", "hello", "https://evil.example"],
        types=["Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/Class;"],
        fields=["Lp/Q;->a:I", "Lp/Q;->b:Ljava/lang/String;"],
        methods=[
            "Lp/Q;-><init>()V",
            "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
        ],
    )


def test_resolve_invoke_method():
    # invoke-static {v1}, method@1
    data = bytes([0x71, 0x10, 0x01, 0x00, 0x01, 0x00])
    inst = decode(data, _pools())[0]
    assert inst.target == "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
    assert inst.to_smali() == (
        "invoke-static v1, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
    )


def test_resolve_const_string():
    # const-string v2, string@2 -> the string literal, not field-or-type
    inst = decode(bytes([0x1A, 0x02, 0x02, 0x00]), _pools())[0]
    assert inst.target == "https://evil.example"


def test_resolve_field_and_type():
    # iget-object v0, v1, field@1 (22c)
    iget = decode(bytes([0x54, 0x10, 0x01, 0x00]), _pools())[0]
    assert iget.target == "Lp/Q;->b:Ljava/lang/String;"
    # new-instance v0, type@2 (21c) -> resolves against the type pool, not strings
    newinst = decode(bytes([0x22, 0x00, 0x02, 0x00]), _pools())[0]
    assert newinst.target == "Ljava/lang/Class;"


def test_resolve_out_of_range_is_none():
    # method index 99 is out of range -> no target, smali falls back to kind@index
    inst = decode(bytes([0x71, 0x10, 0x63, 0x00, 0x01, 0x00]), _pools())[0]
    assert inst.target is None
    assert "method-or-type@99" in inst.to_smali()


def test_opcode_table_format_units_consistent():
    # Every format's unit count equals the leading digit of its id.
    for _, fmt in OPCODES.values():
        assert FORMAT_UNITS[fmt] == int(fmt[0])
