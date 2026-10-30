//! Montgomery arithmetic of a fixed size for SRP-6a's 3072-bit group: numbers as 96 32-bit words (the word of the
//! 32-bit ARMs this runs on; u64 for each product), multiplication with the reduction interleaved (FIOS, Koç, Acar
//! and Kaliski 1996): no division. A modular multiplication with `BigUint` (`a * b % n`) is a product and a long
//! division; its `modpow` is Montgomery's, but general. On an ARM926 at 240 MHz this cuts SRP's M3 from 1.0 s
//! to 0.52 s.

use num_bigint::BigUint;

/// Words of a 3072-bit number.
pub(crate) const WORDS: usize = 96;
/// A number below the modulus, little-endian words, in Montgomery form (x·R mod n, R = 2^3072) unless said.
pub(crate) type Words = [u32; WORDS];

/// The modulus n (odd, 3072 bits) and its constants.
pub(crate) struct Mont {
    big_n: BigUint,
    n: Words,
    /// -n^-1 mod 2^32
    n0: u32,
    /// R^2 mod n: x · R^2 · R^-1 = x · R, into Montgomery form
    r2: Words,
    /// R mod n: 1 in Montgomery form
    one: Words,
}

fn words(x: &BigUint) -> Words {
    let mut w = [0u32; WORDS];
    for (d, s) in w.iter_mut().zip(x.to_u32_digits()) {
        *d = s;
    }
    w
}

impl Mont {
    /// For an odd n of 3072 bits (its top word non-zero).
    pub(crate) fn new(n: &BigUint) -> Self {
        assert!(n.bit(0) && n.bits() > 32 * (WORDS as u64 - 1) && n.bits() <= 32 * WORDS as u64);
        let nw = words(n);
        // n^-1 mod 2^32 by Newton's iteration: each step doubles the correct low bits (1 -> 32 in five)
        let mut inv = 1u32;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(nw[0].wrapping_mul(inv)));
        }
        let r = BigUint::from(1u32) << (32 * WORDS);
        Self {
            big_n: n.clone(),
            n: nw,
            n0: inv.wrapping_neg(),
            r2: words(&(&r * &r % n)),
            one: words(&(&r % n)),
        }
    }

    /// a · b · R^-1 mod n, for a, b < n. The product's word and the reduction's in one pass over t (FIOS): on an
    /// ARM926 the loads and stores of t cost as much as the multiplications.
    pub(crate) fn mul(&self, a: &Words, b: &Words) -> Words {
        // t < 2n throughout: WORDS words and one of carry (0 or 1)
        let mut t = [0u32; WORDS + 1];
        for &bi in b {
            let bi = u64::from(bi);
            // word 0: m makes t[0] + a[0]·bi + m·n[0] end in a zero word
            let s = u64::from(t[0]) + u64::from(a[0]) * bi;
            let m = u64::from((s as u32).wrapping_mul(self.n0));
            let mut c1 = s >> 32;
            let mut c2 = (u64::from(s as u32) + m * u64::from(self.n[0])) >> 32;
            for j in 1..WORDS {
                let s = u64::from(t[j]) + u64::from(a[j]) * bi + c1;
                c1 = s >> 32;
                let s = u64::from(s as u32) + m * u64::from(self.n[j]) + c2;
                c2 = s >> 32;
                t[j - 1] = s as u32;
            }
            let s = u64::from(t[WORDS]) + c1 + c2;
            t[WORDS - 1] = s as u32;
            t[WORDS] = (s >> 32) as u32;
        }
        // t < 2n: t - n if that doesn't borrow, chosen without a branch on the value
        let mut d = [0u32; WORDS];
        let mut borrow = 0u64;
        for j in 0..WORDS {
            let s = u64::from(t[j])
                .wrapping_sub(u64::from(self.n[j]))
                .wrapping_sub(borrow);
            d[j] = s as u32;
            borrow = (s >> 63) & 1;
        }
        // t >= n iff the top word carries or the subtraction didn't borrow
        let keep_t = u32::from(t[WORDS] == 0 && borrow == 1).wrapping_neg();
        let mut out = [0u32; WORDS];
        for j in 0..WORDS {
            out[j] = (t[j] & keep_t) | (d[j] & !keep_t);
        }
        out
    }

    /// x mod n in Montgomery form.
    pub(crate) fn to_mont(&self, x: &BigUint) -> Words {
        let x = if x < &self.big_n {
            words(x)
        } else {
            words(&(x % &self.big_n))
        };
        self.mul(&x, &self.r2)
    }

    /// Out of Montgomery form.
    pub(crate) fn from_mont(&self, a: &Words) -> BigUint {
        let mut unit = [0u32; WORDS];
        unit[0] = 1;
        BigUint::from_slice(&self.mul(a, &unit))
    }

    /// 1 in Montgomery form.
    pub(crate) fn one(&self) -> Words {
        self.one
    }

    /// base^e (Montgomery form in and out), four bits of e at a time from the top: a squaring for each bit and a
    /// multiplication for each four (also by 1 for a zero digit).
    pub(crate) fn pow(&self, base: &Words, e: &BigUint) -> Words {
        let mut table = [self.one; 16];
        for k in 1..16 {
            table[k] = self.mul(&table[k - 1], base);
        }
        let digits = e.bits().div_ceil(4);
        let mut acc = self.one;
        for k in (0..digits).rev() {
            if k + 1 != digits {
                for _ in 0..4 {
                    acc = self.mul(&acc, &acc);
                }
            }
            let d = (0..4).fold(0usize, |d, b| d | usize::from(e.bit(4 * k + b)) << b);
            acc = self.mul(&acc, &table[d]);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n() -> BigUint {
        BigUint::parse_bytes(crate::crypto::pairing_homekit::N_3072_HEX.as_bytes(), 16).unwrap()
    }

    fn samples(n: &BigUint) -> Vec<BigUint> {
        let mut v = vec![
            BigUint::from(0u32),
            BigUint::from(1u32),
            BigUint::from(5u32),
            n - 1u32,
            n - 2u32,
            (BigUint::from(1u32) << 3071u32) + 7u32,
        ];
        let mut x = BigUint::from(0x9e37_79b9_7f4a_7c15u64);
        for _ in 0..20 {
            x = (&x * &x + 0x1234_5678u32) % n;
            v.push(x.clone());
        }
        v
    }

    #[test]
    fn mul_is_modular_multiplication() {
        let n = n();
        let m = Mont::new(&n);
        let s = samples(&n);
        for a in &s {
            for b in s.iter().step_by(3) {
                let got = m.from_mont(&m.mul(&m.to_mont(a), &m.to_mont(b)));
                assert_eq!(got, a * b % &n, "a={a:x} b={b:x}");
            }
        }
    }

    #[test]
    fn pow_is_modpow() {
        let n = n();
        let m = Mont::new(&n);
        let s = samples(&n);
        for (i, base) in s.iter().enumerate() {
            let e = &s[(i * 7 + 3) % s.len()] >> (i * 97 % 2800);
            let got = m.from_mont(&m.pow(&m.to_mont(base), &e));
            assert_eq!(got, base.modpow(&e, &n), "base={base:x} e={e:x}");
        }
        assert_eq!(
            m.from_mont(&m.pow(&m.to_mont(&s[4]), &BigUint::from(0u32))),
            BigUint::from(1u32)
        );
    }

    #[test]
    fn to_mont_reduces_numbers_from_n_up() {
        let n = n();
        let m = Mont::new(&n);
        for x in [n.clone(), &n + 5u32, (&n << 1u32) + 3u32] {
            assert_eq!(m.from_mont(&m.to_mont(&x)), &x % &n);
        }
    }
}
