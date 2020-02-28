// use bellman::pairing::{
//
// };

use bellman::pairing::ff::{
    PrimeField,
    PrimeFieldRepr,
    Field,
    BitIterator,
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit
};

use jubjub::{
    edwards,
    JubjubEngine,
    Unknown,
    PrimeOrder,
    FixedGenerators,
    JubjubParams,
};

use super::num::{
    AllocatedNum,
};

use constants;

use primitives::{
    ValueCommitment,
    ProofGenerationKey,
    PaymentAddress
};

use super::Assignment;
use super::boolean::{Boolean, AllocatedBit};
use super::ecc;
use super::pedersen_hash;
use super::blake2s;
use super::num;
use super::multipack;
use super::ecc::EdwardsPoint;
use super::baby_eddsa::EddsaSignaturePrecomputed;

pub struct Schnorr<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub generator: FixedGenerators,
    pub r: Option<edwards::Point<E, Unknown>>,
    pub h: Option<E::Fs>,
    pub s: Option<E::Fs>,
    pub pk: Option<edwards::Point<E, Unknown>>
}

impl<'a, E: JubjubEngine> Circuit<E> for Schnorr<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        let public_generator = self.params.generator(self.generator).clone();

        let generator = EdwardsPoint::witness(cs.namespace(|| "allocate public generator"), Some(public_generator), self.params).unwrap();

        let r = EdwardsPoint::witness(cs.namespace(|| "allocate r"), self.r.clone(), self.params).unwrap();

        let pk = EdwardsPoint::witness(cs.namespace(|| "allocate pk"), self.pk.clone(), self.params).unwrap();

        let s = if self.s.is_some() {
            self.s.unwrap()
        } else {
            E::Fs::zero()
        };

        let h = if self.h.is_some() {
            self.h.unwrap()
        } else {
            E::Fs::zero()
        };

        let mut h_bits = BitIterator::new(h.clone().into_repr()).collect::<Vec<_>>();
        h_bits.reverse();
        h_bits.truncate(E::Fs::NUM_BITS as usize);

        let h_bits = h_bits.into_iter()
                           .enumerate()
                           .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("h bit {}", i)), Some(b)).unwrap())
                           .map(|v| Boolean::from(v))
                           .collect::<Vec<_>>();

        let s = self.s.clone();
        let sig = EddsaSignaturePrecomputed{r, s, pk};
        sig.verify_schnorr_blake2s_precomputed(cs.namespace(|| "verify sig"), self.params, &h_bits, generator)?;

        Ok(())
    }
}
