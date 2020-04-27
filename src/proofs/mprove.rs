#![allow(non_snake_case)]

/*

Copyright 2020 by Suyash Bagad, Saravanan Vijayakumaran

This file is part of MProvelibrary
(<add a link to github>)

*/

// based on the paper: <link to paper>
use curv::arithmetic::traits::{Converter};
use curv::BigInt;
use Errors::{self, MProveError};
use proofs::mprove_sigs::*;

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::scalar::Scalar;

#[derive(Clone, Debug)]
pub struct MProve {
    C_vec: Vec<RistrettoPoint>,
    P_vec: Vec<RistrettoPoint>,
    C_prime_vec: Vec<RistrettoPoint>,
    C_res: RistrettoPoint,
    gamma_vec: Vec<RingSig>,
    sigma_vec: Vec<LSAGSig>,
    message: RistrettoPoint,
}

impl MProve{

    pub fn prove(
        // crs
        G: &RistrettoPoint,
        // stmt
        C_vec: &[RistrettoPoint], // vector of commitments
        P_vec: &[RistrettoPoint], // addresses in the ring (public keys)
        // witness
        x_vec: &[Scalar], // secret keys
        E_vec: &[BigInt], // locations of exchange-owned keys
    ) -> MProve {

        // ring size
        let n: usize = P_vec.len();
        let mut rng = rand::thread_rng();

        let mut C_prime_vec: Vec<RistrettoPoint> = vec![*G; n];
        let mut gamma_vec = (0..n).map(|_| RingSig::initialize(n)).collect::<Vec<RingSig>>();
        let mut sigma_vec = (0..n).map(|_| LSAGSig::initialize(n)).collect::<Vec<LSAGSig>>();

        let message = RistrettoPoint::random(&mut rng);
        let z_vec: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let mut index: usize = 0;
        let C_res_vec: Vec<RistrettoPoint> = (0..n)
            .map(|i| {
                let bignum_bit: BigInt = &E_vec[i].clone() & BigInt::one();
                let byte = BigInt::to_vec(&bignum_bit);
                if byte[0]==1 {
                    // compute C_prime_i
                    // let z_i = Scalar::random(&mut rng);
                    C_prime_vec[i] = G * z_vec[i];

                    // construct pk vectors
                    let C_primei_Ci = C_prime_vec[i] - C_vec[i];
                    let pk_gamma = vec![C_prime_vec[i], C_primei_Ci];
                    let pk_sigma = vec![P_vec[i], C_primei_Ci];

                    // gen ring signatures
                    gamma_vec[i] = RingSig::gen_RingSig(message, &pk_gamma, z_vec[i], 0);
                    sigma_vec[i] = LSAGSig::gen_LSAG(message, &pk_sigma, x_vec[index], 0);
                    index = index + 1;

                    C_primei_Ci
                }
                else {
                    // compute C_prime_i
                    // let z_i = ECScalar::new_random();
                    let C_primei_Ci = G * z_vec[i]; 
                    C_prime_vec[i] = C_primei_Ci + C_vec[i];

                    // construct pk vectors
                    let pk_gamma = vec![C_prime_vec[i], C_primei_Ci];
                    let pk_sigma = vec![P_vec[i], C_primei_Ci];

                    // gen ring signatures
                    gamma_vec[i] = RingSig::gen_RingSig(message, &pk_gamma, z_vec[i], 1);
                    sigma_vec[i] = LSAGSig::gen_LSAG(message, &pk_sigma, z_vec[i], 1);

                    C_primei_Ci
                }
            })
            .collect();
        
        let one_vec: Vec<Scalar> = (0..n).map(|_| Scalar::one()).collect();
        let C_res = RistrettoPoint::vartime_multiscalar_mul(one_vec.iter(), C_res_vec.iter());

        return MProve{
            C_vec: C_vec.to_vec(),
            P_vec: P_vec.to_vec(),
            C_prime_vec,
            C_res,
            gamma_vec,
            sigma_vec,
            message,
        };
    }

    pub fn verify(
        &self,
    ) -> Result<(), Errors> {

        // ring size
        let n: usize = self.P_vec.len();
        
        // calculated C_res
        let C_sub_vec: Vec<RistrettoPoint> = (0..n)
            .map(|i| {
                self.C_prime_vec[i] - self.C_vec[i]
            })
            .collect();

        let one_vec: Vec<Scalar> = (0..n).map(|_| Scalar::one()).collect();
        let C_res_comp = RistrettoPoint::vartime_multiscalar_mul(one_vec.iter(), C_sub_vec.iter());

        // verify ring signatures
        for i in 0..n {

            // construct pk vectors
            let pk_gamma = vec![self.C_prime_vec[i], C_sub_vec[i]];
            let pk_sigma = vec![self.P_vec[i], C_sub_vec[i]];

            let ring_res = self.gamma_vec[i].ver_RingSig(self.message, &pk_gamma);
            let LSAG_res = self.sigma_vec[i].ver_LSAG(self.message, &pk_sigma);

            assert!(ring_res.is_ok(), "Ring signature verification failed at index {}", i);
            assert!(LSAG_res.is_ok(), "LSAG signature verification failed at index {}", i);  
        }

        if C_res_comp==self.C_res {
            Ok(())
        } else {
            Err(MProveError)
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;
    use rand::distributions::{Distribution, Uniform};
    use std::time::{Instant};
    use rand::Rng;
    use curve25519_dalek::constants;
    use sha2::Sha512;
    
    use std::fs::File;
    use flame as f;

    pub fn test_mprove(n: usize, s: usize){
                
        // generate random amounts in range {0,..,2^{amt_bit_range}}
        let mut rng = rand::thread_rng();
        let a_vec: Vec<Scalar> = (0..s).map(|_| Scalar::from(rng.gen::<u32>())).collect();
        
        // generate blinding factors
        let r_vec: Vec<Scalar> = (0..s).map(|_| Scalar::random(&mut rng)).collect();

        // generate secret keys
        let x_vec: Vec<Scalar> = (0..s).map(|_| Scalar::random(&mut rng)).collect();

        // G, H - curve points for generating outputs and key-images
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
    
        // generate P_vec, C_vec
        let mut P_vec: Vec<RistrettoPoint> = (0..n)
            .map(|_| {
                RistrettoPoint::random(&mut rng)
            })
            .collect();

        // Select random commitments inclusing those owned by the exchange
        let mut C_vec_mut: Vec<RistrettoPoint> = (0..n)
            .map(|_| {
                RistrettoPoint::random(&mut rng)
            })
            .collect();
        
        // generate random index vector of size s
        let setsize = n / s;
        let mut start_idx = 0;
        let mut end_idx = cmp::max(1, setsize-1);
        let idx = (0..s).map(|_| {
            
            let dist1 = Uniform::from(start_idx..end_idx);
            start_idx = setsize + start_idx;
            end_idx =  cmp::min(n-1, end_idx + setsize);

            dist1.sample(&mut rng)
        })
        .collect::<Vec<usize>>();

        let mut index = 0;
        let E_vec = (0..n)
            .map(|i| {
                if index < idx.len() {
                    if i == idx[index] {
                        // generate commitments using a_vec, r_vec
                        C_vec_mut[i as usize] = G * r_vec[index] + H * a_vec[index];
                        P_vec[i as usize] = G * x_vec[index];
                        index = index + 1;
                        BigInt::one()
                    }
                    else {
                        BigInt::zero()
                    }
                }
                else{
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();            
        
        let _fg = ::flame::start_guard("test_mprove");
        
        println!("(n={}, s={})", n, s);
        let start = Instant::now();
        let mprove_sample = MProve::prove(&G, &C_vec_mut, &P_vec, &x_vec, &E_vec);
        let duration = start.elapsed();
        println!("MProve gen time: {:?}", duration);

        let start = Instant::now();
        let result = mprove_sample.verify();
        let duration = start.elapsed();
        println!("MProve ver time: {:?}\n", duration);

        assert!(result.is_ok());
    }

    #[test]
    pub fn sim_mprove(){
        // test_mprove(20, 4);
        // test_mprove(20, 16);
        // test_mprove(100, 50);
        test_mprove(1000, 100);
    }

    #[test]
    pub fn gen_profile(){
        let _fg = ::flame::start_guard("sim_mprove");
        test_mprove(2, 1);
        _fg.end();

        // save flamegraph to a json file
        f::dump_html(File::create("flamegraph.html").unwrap()).unwrap();
        f::dump_json(&mut File::create("flamegraph.json").unwrap()).unwrap();
    }

}