#![feature(test)]

extern crate rand;
extern crate test;
extern crate bellman_ce as bellman;
extern crate franklin_crypto;

use rand::{Rand, thread_rng};
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use franklin_crypto::pedersen_hash::{pedersen_hash, Personalization};
use franklin_crypto::eddsa::{Seed, PrivateKey, PublicKey};
use bellman::pairing::bn256::{Bn256, Fr};
use rand::{SeedableRng, Rng, XorShiftRng};

#[bench]
fn bench_baby_schnorr(b: &mut test::Bencher) {
      let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let params = &AltJubjubBn256::new();
    let mut cs = TestConstraintSystem::<Bn256>::new();
    let sk = PrivateKey::<Bn256>(rng.gen());
    let vk = PublicKey::from_private(&sk, p_g, params);
}
