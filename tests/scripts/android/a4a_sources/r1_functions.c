/*
 * A4a R1 — one function, one mode: ~10 plain functions, no interworking.
 *
 * Built for all five ABIs with NDK r28 clang -g -shared -fPIC -fno-inline,
 * and for armeabi-v7a twice more with -mthumb / -marm, by
 * tests/scripts/android/build_a4a_fixtures.py. Every helper is static and
 * noinline so the symbol table keeps ten real functions (a plain -O2 build
 * inlines them all away), and the stripped twin (R3) keeps them out of
 * .dynsym so discovery has to come from the unwind tables; a4a_r1_run is the
 * single export.
 *
 * The call shape is deliberately explicit so the source itself is a call-list
 * oracle:
 *
 *   a4a_r1_run -> add_mod, mul_acc, first_set, byte_sum, rotl32,
 *                 mix32, stretch, weighted, smooth
 *   weighted   -> mul_acc, add_mod
 *   smooth     -> byte_sum, mix32
 */

#define NOINLINE __attribute__((noinline))

static NOINLINE unsigned add_mod(unsigned a, unsigned b)
{
    return (a + b) % 1000003u;
}

static NOINLINE unsigned mul_acc(const unsigned *values, unsigned count)
{
    unsigned acc = 1;
    for (unsigned i = 0; i < count; i++) {
        acc = add_mod(acc * 3u, values[i]);
    }
    return acc;
}

static NOINLINE int first_set(unsigned value)
{
    for (int bit = 0; bit < 32; bit++) {
        if (value & (1u << bit)) {
            return bit;
        }
    }
    return -1;
}

static NOINLINE unsigned byte_sum(const unsigned char *data, unsigned count)
{
    unsigned total = 0;
    for (unsigned i = 0; i < count; i++) {
        total += data[i];
    }
    return total;
}

static NOINLINE unsigned rotl32(unsigned value, unsigned shift)
{
    shift &= 31u;
    return (value << shift) | (value >> (32u - shift));
}

static NOINLINE unsigned mix32(unsigned value)
{
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static NOINLINE unsigned stretch(unsigned value)
{
    unsigned out = value;
    for (int round = 0; round < 4; round++) {
        out = rotl32(out ^ (unsigned) round, 3 + round) + 0x9e3779b9u;
    }
    return out;
}

static NOINLINE unsigned weighted(const unsigned *values, unsigned count)
{
    unsigned hi = mul_acc(values, count);
    unsigned lo = add_mod(hi, count);
    return hi ^ lo;
}

static NOINLINE unsigned smooth(const unsigned char *data, unsigned count)
{
    unsigned sum = byte_sum(data, count);
    return mix32(sum ^ count);
}

int a4a_r1_run(unsigned seed)
{
    static const unsigned table[8] = {
        2u, 3u, 5u, 7u, 11u, 13u, 17u, 19u,
    };
    static const unsigned char bytes[12] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04,
    };
    unsigned a = add_mod(seed, table[seed & 7u]);
    unsigned b = mul_acc(table, 8u);
    int c = first_set(a ^ b);
    unsigned d = byte_sum(bytes, 12u);
    unsigned e = rotl32((unsigned) c + d, 7u);
    unsigned f = mix32(e);
    unsigned g = stretch(f);
    unsigned h = weighted(table, 8u);
    unsigned i = smooth(bytes, 12u);
    return (int) ((g ^ h ^ i) + (unsigned) c);
}
