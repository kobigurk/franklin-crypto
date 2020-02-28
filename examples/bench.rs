extern crate franklin_crypto;
extern crate bellman_ce as bellman;
extern crate rand;

use std::time::{Duration, Instant};

use bellman::pairing::ff::{
    PrimeField,
    PrimeFieldRepr,
    Field,
};



use franklin_crypto::alt_babyjubjub::{AltJubjubBn256, fs, edwards, FixedGenerators};
use franklin_crypto::circuit::schnorr::{
    Schnorr
};
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Seed, Signature};

use bellman::groth16::*;
use rand::{XorShiftRng, SeedableRng, Rng};
use bellman::pairing::bn256::{Bn256, Fr};

fn main() {
    let jubjub_params = &AltJubjubBn256::new();
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    println!("Creating sample parameters...");
    let groth_params = generate_random_parameters::<Bn256, _, _>(
        Schnorr {
            params: jubjub_params,
            generator: p_g,
            r: None,
            h: None,
            s: None,
            pk: None,
        },
        rng
    ).unwrap();

    const SAMPLES: u32 = 50;

    let mut total_time = Duration::new(0, 0);
    for _ in 0..SAMPLES {
        let start = Instant::now();

        let sk = PrivateKey::<Bn256>(rng.gen());
        let vk = PublicKey::from_private(&sk, p_g, jubjub_params);
        let msg = b"Foo bar";
        let seed = Seed::random_seed(rng, msg);
        let sig = sk.sign_schnorr_blake2s(msg, &seed, p_g, jubjub_params);
        assert!(vk.verify_schnorr_blake2s(msg, &sig, p_g, jubjub_params));

        /*
        let mut s_bytes = [0u8; 32];
        sig.s.into_repr().write_le(& mut s_bytes[..]).expect("get LE bytes of signature S");
        let mut s_repr = <Fr as PrimeField>::Repr::from(0);
        s_repr.read_le(&s_bytes[..]).expect("interpret S as field element representation");

        let mut h_bytes = [0u8; 32];
        sig.h.into_repr().write_le(& mut h_bytes[..]).expect("get LE bytes of signature H");
        let mut h_repr = <Fr as PrimeField>::Repr::from(0);
        h_repr.read_le(&h_bytes[..]).expect("interpret H as field element representation");
        */

        let _ = create_random_proof(Schnorr {
            params: jubjub_params,
            generator: p_g,
            r: Some(sig.r),
            h: Some(sig.h),
            s: Some(sig.s),
            pk: Some(vk.0),
        }, &groth_params, rng).unwrap();
        total_time += start.elapsed();
    }
    let avg = total_time / SAMPLES;
    let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64
              + (avg.as_secs() as f64);

    println!("Average proving time (in seconds): {}", avg);
}
