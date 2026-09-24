/*
 * A4a R2 — ARM32 interworking: Thumb <-> ARM bl/blx, bx lr, pop {..., pc},
 * literal pools, tbb/tbh switch tables, and the $a/$t/$d mapping symbols the
 * assembler emits for the mode changes.
 *
 * The ARM/Thumb attribute tricks are guarded to __arm__ so the same file
 * builds for every ABI (the switch tables and call chains stay); the
 * armeabi-v7a build is where the interworking oracle lives. Built by
 * tests/scripts/android/build_a4a_fixtures.py with NDK r28 clang -g
 * -fno-inline. Every helper is noinline and the switch cases call distinct
 * helpers, so the compiler cannot fold a table lookup over the results and
 * emits real jump tables (tbb/tbh in Thumb).
 *
 * Source call-list oracle (armeabi-v7a):
 *   a4a_r2_run        -> thumb_dispatcher, arm_state_step, thumb_table_jump,
 *                        wide_table_jump, pool_reader
 *   thumb_dispatcher  -> arm_leaf, thumb_leaf, arm_state_step
 *   arm_state_step    -> arm_leaf, thumb_leaf
 *   thumb_table_jump  -> hop0..hop15 (one per case, via the tbb table)
 *   wide_table_jump   -> span0..span15 (via the tbh table)
 *   pool_reader       -> arm_state_step, arm_absolute
 */

#if defined(__arm__)
#define ARM_CODE __attribute__((target("arm")))
#define THUMB_CODE __attribute__((target("thumb")))
#else
#define ARM_CODE
#define THUMB_CODE
#endif
#define NOINLINE __attribute__((noinline))

static volatile unsigned g_sink;

static ARM_CODE NOINLINE unsigned arm_leaf(unsigned x)
{
    return (x * 31u) ^ 0x5a5au;
}

static THUMB_CODE NOINLINE unsigned thumb_leaf(unsigned x)
{
    return (x + 17u) ^ 0xa5a5u;
}

/* Sixteen distinct noinline case bodies: the switch cannot become a
 * constant-table lookup, so Thumb code emits a tbb byte jump table. */
static NOINLINE unsigned hop0(unsigned x) { return x + 1u; }
static NOINLINE unsigned hop1(unsigned x) { return x * 2u + 1u; }
static NOINLINE unsigned hop2(unsigned x) { return x ^ 2u; }
static NOINLINE unsigned hop3(unsigned x) { return x + 5u; }
static NOINLINE unsigned hop4(unsigned x) { return x * 3u + 2u; }
static NOINLINE unsigned hop5(unsigned x) { return x ^ 6u; }
static NOINLINE unsigned hop6(unsigned x) { return x + 9u; }
static NOINLINE unsigned hop7(unsigned x) { return x * 5u + 4u; }
static NOINLINE unsigned hop8(unsigned x) { return x ^ 10u; }
static NOINLINE unsigned hop9(unsigned x) { return x + 13u; }
static NOINLINE unsigned hop10(unsigned x) { return x * 7u + 6u; }
static NOINLINE unsigned hop11(unsigned x) { return x ^ 14u; }
static NOINLINE unsigned hop12(unsigned x) { return x + 17u; }
static NOINLINE unsigned hop13(unsigned x) { return x * 11u + 8u; }
static NOINLINE unsigned hop14(unsigned x) { return x ^ 22u; }
static NOINLINE unsigned hop15(unsigned x) { return x + 25u; }

/* The case values below are irregular by construction (a fixed seeded
 * sequence of 3/4/5 gaps, 177 cases over a 696 span): no shift, rotation or
 * comparison tree wins, and the table exceeds 255 bytes, so Thumb code
 * emits a tbh halfword jump table. Verified in the same run that builds it. */
static NOINLINE unsigned span0(unsigned x) { return x + 31u; }
static NOINLINE unsigned span1(unsigned x) { return x * 13u + 1u; }
static NOINLINE unsigned span2(unsigned x) { return x ^ 26u; }
static NOINLINE unsigned span3(unsigned x) { return x + 33u; }
static NOINLINE unsigned span4(unsigned x) { return x * 17u + 2u; }
static NOINLINE unsigned span5(unsigned x) { return x ^ 34u; }
static NOINLINE unsigned span6(unsigned x) { return x + 39u; }
static NOINLINE unsigned span7(unsigned x) { return x * 19u + 3u; }
static NOINLINE unsigned span8(unsigned x) { return x ^ 38u; }
static NOINLINE unsigned span9(unsigned x) { return x + 41u; }
static NOINLINE unsigned span10(unsigned x) { return x * 23u + 4u; }
static NOINLINE unsigned span11(unsigned x) { return x ^ 46u; }
static NOINLINE unsigned span12(unsigned x) { return x + 43u; }
static NOINLINE unsigned span13(unsigned x) { return x * 29u + 5u; }
static NOINLINE unsigned span14(unsigned x) { return x ^ 58u; }
static NOINLINE unsigned span15(unsigned x) { return x + 51u; }

static THUMB_CODE NOINLINE unsigned thumb_table_jump(unsigned index)
{
    switch (index & 15u) {
        case 0: return hop0(index) + 1u;
        case 1: return hop1(index) + 2u;
        case 2: return hop2(index) + 3u;
        case 3: return hop3(index) + 5u;
        case 4: return hop4(index) + 7u;
        case 5: return hop5(index) + 11u;
        case 6: return hop6(index) + 13u;
        case 7: return hop7(index) + 17u;
        case 8: return hop8(index) + 19u;
        case 9: return hop9(index) + 23u;
        case 10: return hop10(index) + 29u;
        case 11: return hop11(index) + 31u;
        case 12: return hop12(index) + 37u;
        case 13: return hop13(index) + 41u;
        case 14: return hop14(index) + 43u;
        default: return hop15(index) + 47u;
    }
}

static THUMB_CODE NOINLINE unsigned wide_table_jump(unsigned index)
{
    switch (index & 1023u) {
        case 0: return span0(index) + 0u;
        case 4: return span4(index) + 4u;
        case 7: return span7(index) + 7u;
        case 11: return span11(index) + 11u;
        case 16: return span0(index) + 16u;
        case 19: return span3(index) + 19u;
        case 22: return span6(index) + 22u;
        case 27: return span11(index) + 27u;
        case 30: return span14(index) + 30u;
        case 34: return span2(index) + 3u;
        case 39: return span7(index) + 8u;
        case 42: return span10(index) + 11u;
        case 47: return span15(index) + 16u;
        case 50: return span2(index) + 19u;
        case 53: return span5(index) + 22u;
        case 56: return span8(index) + 25u;
        case 60: return span12(index) + 29u;
        case 64: return span0(index) + 2u;
        case 67: return span3(index) + 5u;
        case 70: return span6(index) + 8u;
        case 73: return span9(index) + 11u;
        case 78: return span14(index) + 16u;
        case 82: return span2(index) + 20u;
        case 85: return span5(index) + 23u;
        case 90: return span10(index) + 28u;
        case 93: return span13(index) + 0u;
        case 96: return span0(index) + 3u;
        case 101: return span5(index) + 8u;
        case 106: return span10(index) + 13u;
        case 111: return span15(index) + 18u;
        case 114: return span2(index) + 21u;
        case 119: return span7(index) + 26u;
        case 124: return span12(index) + 0u;
        case 128: return span0(index) + 4u;
        case 131: return span3(index) + 7u;
        case 134: return span6(index) + 10u;
        case 137: return span9(index) + 13u;
        case 142: return span14(index) + 18u;
        case 145: return span1(index) + 21u;
        case 149: return span5(index) + 25u;
        case 153: return span9(index) + 29u;
        case 156: return span12(index) + 1u;
        case 161: return span1(index) + 6u;
        case 164: return span4(index) + 9u;
        case 169: return span9(index) + 14u;
        case 173: return span13(index) + 18u;
        case 178: return span2(index) + 23u;
        case 183: return span7(index) + 28u;
        case 186: return span10(index) + 0u;
        case 189: return span13(index) + 3u;
        case 194: return span2(index) + 8u;
        case 199: return span7(index) + 13u;
        case 204: return span12(index) + 18u;
        case 207: return span15(index) + 21u;
        case 211: return span3(index) + 25u;
        case 214: return span6(index) + 28u;
        case 219: return span11(index) + 2u;
        case 224: return span0(index) + 7u;
        case 227: return span3(index) + 10u;
        case 232: return span8(index) + 15u;
        case 235: return span11(index) + 18u;
        case 240: return span0(index) + 23u;
        case 243: return span3(index) + 26u;
        case 247: return span7(index) + 30u;
        case 252: return span12(index) + 4u;
        case 257: return span1(index) + 9u;
        case 261: return span5(index) + 13u;
        case 265: return span9(index) + 17u;
        case 269: return span13(index) + 21u;
        case 274: return span2(index) + 26u;
        case 278: return span6(index) + 30u;
        case 282: return span10(index) + 3u;
        case 286: return span14(index) + 7u;
        case 289: return span1(index) + 10u;
        case 292: return span4(index) + 13u;
        case 297: return span9(index) + 18u;
        case 300: return span12(index) + 21u;
        case 303: return span15(index) + 24u;
        case 308: return span4(index) + 29u;
        case 312: return span8(index) + 2u;
        case 317: return span13(index) + 7u;
        case 321: return span1(index) + 11u;
        case 325: return span5(index) + 15u;
        case 330: return span10(index) + 20u;
        case 334: return span14(index) + 24u;
        case 338: return span2(index) + 28u;
        case 343: return span7(index) + 2u;
        case 346: return span10(index) + 5u;
        case 349: return span13(index) + 8u;
        case 354: return span2(index) + 13u;
        case 358: return span6(index) + 17u;
        case 361: return span9(index) + 20u;
        case 365: return span13(index) + 24u;
        case 368: return span0(index) + 27u;
        case 372: return span4(index) + 0u;
        case 376: return span8(index) + 4u;
        case 379: return span11(index) + 7u;
        case 384: return span0(index) + 12u;
        case 387: return span3(index) + 15u;
        case 392: return span8(index) + 20u;
        case 397: return span13(index) + 25u;
        case 401: return span1(index) + 29u;
        case 405: return span5(index) + 2u;
        case 410: return span10(index) + 7u;
        case 414: return span14(index) + 11u;
        case 419: return span3(index) + 16u;
        case 423: return span7(index) + 20u;
        case 428: return span12(index) + 25u;
        case 432: return span0(index) + 29u;
        case 435: return span3(index) + 1u;
        case 438: return span6(index) + 4u;
        case 442: return span10(index) + 8u;
        case 446: return span14(index) + 12u;
        case 451: return span3(index) + 17u;
        case 456: return span8(index) + 22u;
        case 459: return span11(index) + 25u;
        case 462: return span14(index) + 28u;
        case 467: return span3(index) + 2u;
        case 472: return span8(index) + 7u;
        case 476: return span12(index) + 11u;
        case 481: return span1(index) + 16u;
        case 486: return span6(index) + 21u;
        case 491: return span11(index) + 26u;
        case 495: return span15(index) + 30u;
        case 499: return span3(index) + 3u;
        case 504: return span8(index) + 8u;
        case 508: return span12(index) + 12u;
        case 513: return span1(index) + 17u;
        case 517: return span5(index) + 21u;
        case 520: return span8(index) + 24u;
        case 524: return span12(index) + 28u;
        case 528: return span0(index) + 1u;
        case 531: return span3(index) + 4u;
        case 536: return span8(index) + 9u;
        case 539: return span11(index) + 12u;
        case 543: return span15(index) + 16u;
        case 546: return span2(index) + 19u;
        case 549: return span5(index) + 22u;
        case 553: return span9(index) + 26u;
        case 556: return span12(index) + 29u;
        case 561: return span1(index) + 3u;
        case 564: return span4(index) + 6u;
        case 568: return span8(index) + 10u;
        case 572: return span12(index) + 14u;
        case 576: return span0(index) + 18u;
        case 579: return span3(index) + 21u;
        case 582: return span6(index) + 24u;
        case 586: return span10(index) + 28u;
        case 590: return span14(index) + 1u;
        case 595: return span3(index) + 6u;
        case 599: return span7(index) + 10u;
        case 602: return span10(index) + 13u;
        case 606: return span14(index) + 17u;
        case 611: return span3(index) + 22u;
        case 615: return span7(index) + 26u;
        case 620: return span12(index) + 0u;
        case 624: return span0(index) + 4u;
        case 628: return span4(index) + 8u;
        case 633: return span9(index) + 13u;
        case 637: return span13(index) + 17u;
        case 640: return span0(index) + 20u;
        case 643: return span3(index) + 23u;
        case 646: return span6(index) + 26u;
        case 649: return span9(index) + 29u;
        case 652: return span12(index) + 1u;
        case 655: return span15(index) + 4u;
        case 660: return span4(index) + 9u;
        case 663: return span7(index) + 12u;
        case 666: return span10(index) + 15u;
        case 670: return span14(index) + 19u;
        case 675: return span3(index) + 24u;
        case 678: return span6(index) + 27u;
        case 682: return span10(index) + 0u;
        case 686: return span14(index) + 4u;
        case 689: return span1(index) + 7u;
        case 692: return span4(index) + 10u;
        case 696: return span8(index) + 14u;
        default: return span15(index) + 3u;
    }
}

/* ARM-mode callee: keeps a frame and returns with bx lr; the address of
 * arm_absolute below is materialised through an ARM literal pool here. */
static ARM_CODE NOINLINE unsigned arm_state_step(unsigned state)
{
    static const unsigned constants[4] = {
        0x13572468u, 0x2468ace0u, 0xbecca1f0u, 0x0ddba11u,
    };
    unsigned picked = constants[state & 3u];
    unsigned mixed = arm_leaf(state) + thumb_leaf(state >> 1);
    return picked ^ mixed;
}

static ARM_CODE NOINLINE const unsigned *arm_absolute(void)
{
    static const unsigned anchor[2] = { 0x600df00du, 0x2bad4d5u };
    return anchor;
}

/* ARM reader of a Thumb-computed index; the address load from arm_absolute
 * is the PC-relative literal-pool load the rung wants in ARM code. */
static ARM_CODE NOINLINE unsigned pool_reader(unsigned state)
{
    const unsigned *anchor = arm_absolute();
    return arm_state_step(state) + anchor[state & 1u];
}

/* Thumb caller of ARM callees (blx with mode switch) and Thumb callees. */
static THUMB_CODE NOINLINE unsigned thumb_dispatcher(unsigned code)
{
    unsigned left = arm_leaf(code);
    unsigned right = thumb_leaf(code + 1u);
    if (code & 1u) {
        return left ^ right;
    }
    unsigned stepped = arm_state_step(code);
    return left + right + stepped;
}

int a4a_r2_run(unsigned input)
{
    unsigned out = 0;
    out += thumb_dispatcher(input);
    out += arm_state_step(input >> 2);
    out += thumb_table_jump(input);
    out += wide_table_jump(input >> 1);
    out += pool_reader(input >> 3);
    g_sink = out;
    return (int) out;
}
