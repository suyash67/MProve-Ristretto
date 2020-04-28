#![allow(non_snake_case)]

/*

Copyright 2020 by Suyash Bagad, Saravanan Vijayakumaran

This file is part of mProve library
(<add a link to github>)

*/

// based on the paper: <link to paper>

use Errors::{self, MProveSigsError};
use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants;
// use sha2::Sha512;
use sha3::Keccak512;


#[derive(Clone, Debug)]
pub struct RingSig{
    s_vec: Vec<Scalar>,
    c: Scalar,
}

impl RingSig{
    pub fn gen_RingSig(
        message: RistrettoPoint,
        pk: &[RistrettoPoint],
        x: Scalar,
        index: usize,
    ) -> RingSig {

        // let _fg = ::flame::start_guard("gen RS");

        // ring size
        let n = pk.len();
        let mut rng = rand::thread_rng();
        assert!(n >= 2, "Error! Why ring signature if cols = 1!");
        assert!(index < n, "Index out of range");

        // Pick alpha and s_i \in {1,2,...,q-1}, i = 0,1,...,n-1
        let alpha = Scalar::random(&mut rng);
        let mut s_vec: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        // Compute L_j
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let L_j = G * alpha;
        
        // Construct a vector of EC points to hash
        let mut tohash_vec: Vec<u8> = Vec::new();
        for i in 0..n {
            tohash_vec.extend_from_slice(pk[i].compress().as_bytes());
        }
        tohash_vec.extend_from_slice(message.compress().as_bytes());
        tohash_vec.extend_from_slice(L_j.compress().as_bytes());

        let mut c_old = Scalar::hash_from_bytes::<Keccak512>(&tohash_vec);

        // compute c0
        let mut j = (index + 1)%n;
        let mut c = Scalar::one();
        if j == 0 {
            c = c_old;
        }

        // computing (j mod n) points and integers
        while j != index {
            // compute L
            s_vec[j] = Scalar::random(&mut rng);
            // let sG = G * s_vec[j];
            // let cpk_j = pk[j] * c_old;
            // let L = sG + cpk_j;
            let L = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c_old, &pk[j], &s_vec[j]);

            // compute c_old
            let idx = (n+1)*32;
            tohash_vec[idx..].copy_from_slice(L.compress().as_bytes());
            c_old = Scalar::hash_from_bytes::<Keccak512>(&tohash_vec);
            
            j = (j + 1) % n;

            if j == 0 {
                c = c_old;
            }
        }

        // compute s_j
        s_vec[index] = alpha - (c_old * x);

        return RingSig {
            s_vec,
            c,
        };
    }

    pub fn ver_RingSig(
        &self,
        message: RistrettoPoint,
        pk: &[RistrettoPoint],
    ) -> Result<(), Errors> {

        // let _fg = ::flame::start_guard("ver RS");
        
        // ring size
        let n = pk.len();
        assert!(n >= 2, "Error! Why ring signature if cols = 1!");
        assert!(self.s_vec.len() == n, "Bad rs.s_vec size.");

        // check if any element of s_vec or c is 0
        for i in 0..n {
            assert!(self.s_vec[i] != Scalar::zero(), "s_vec cannot have a 0 element!");
        }
        assert!(self.c != Scalar::zero(), "c cannot be 0!");

        // Construct a vector of EC points to hash
        let mut tohash_vec: Vec<u8> = Vec::new();
        for i in 0..n {
            tohash_vec.extend_from_slice(pk[i].compress().as_bytes());
        }
        tohash_vec.extend_from_slice(message.compress().as_bytes());
        tohash_vec.extend_from_slice(message.compress().as_bytes());

        // compute c_j's
        let mut j: usize = 0;
        let mut c_old = self.c;
        let idx = (n+1)*32;
        while j < n {
            // let sG = G * self.s_vec[j];
            // let cpk_j = pk[j] * c_old;
            // let L = sG + cpk_j;
            let L = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c_old, &pk[j], &self.s_vec[j]);

            tohash_vec[idx..].copy_from_slice(L.compress().as_bytes());
            c_old = Scalar::hash_from_bytes::<Keccak512>(&tohash_vec);
            j = j + 1;
        }

        if c_old == self.c {
            Ok(())
        } else {
            Err(MProveSigsError)
        }
    }

    pub fn initialize(n: usize) -> RingSig {

        // let _fg = ::flame::start_guard("initialize sig");

        // function to initialize a RingSig variable
        let s_vec = (0..n).map(|_| { Scalar::one()}).collect::<Vec<Scalar>>();
        let c = Scalar::one();

        return RingSig {
            s_vec,
            c,
        };
    }
}

#[derive(Clone, Debug)]
pub struct LSAGSig{
    s_vec: Vec<Scalar>,
    c: Scalar,
    I: RistrettoPoint,
}

impl LSAGSig{
    pub fn gen_LSAG(
        message: RistrettoPoint,
        pk: &[RistrettoPoint],
        x: Scalar,
        index: usize,
    ) -> LSAGSig {

        // let _fg = ::flame::start_guard("gen LSAG");

        // ring size
        let n = pk.len();
        let mut rng = rand::thread_rng();
        assert!(n >= 2, "Error! Why ring signature if cols = 1!");
        assert!(index < n, "Index out of range");

        // let _fgI = ::flame::start_guard("I");
        // compute key-image
        let H_P_idx = RistrettoPoint::hash_from_bytes::<Keccak512>(pk[index].compress().as_bytes());
        let I = H_P_idx * x;
        // _fgI.end();

        // Pick alpha and s_i \in {1,2,...,q-1}, i = 0,1,...,n-1
        let alpha = Scalar::random(&mut rng);
        let mut s_vec: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        // let _fgLR = ::flame::start_guard("L,R");
        // Compute L_j and R_j
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let L_j = G * alpha;
        let R_j = H_P_idx * alpha;
        // _fgLR.end();

        // Construct a vector of EC points to hash
        let mut tohash_vec: Vec<u8> = Vec::new();
        for i in 0..n {
            tohash_vec.extend_from_slice(pk[i].compress().as_bytes());
        }
        tohash_vec.extend_from_slice(message.compress().as_bytes());
        tohash_vec.extend_from_slice(L_j.compress().as_bytes());
        tohash_vec.extend_from_slice(R_j.compress().as_bytes());

        let mut c_old = Scalar::hash_from_bytes::<Keccak512>(&tohash_vec);        

        // compute c0
        let mut j = (index + 1)%n;
        let mut c = Scalar::one();
        if j == 0 {
            c = c_old;
        }

        // computing (j mod n) points and integers
        let idxL = (n+1)*32;
        let idxR = (n+2)*32;
        while j != index {

            // compute L
            // let _fgL = ::flame::start_guard("L");
            s_vec[j] = Scalar::random(&mut rng);
            // let sG = G * s_vec[j];
            // let cpk_j = pk[j] * c_old;
            // let L = sG + cpk_j;
            let L = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c_old, &pk[j], &s_vec[j]);
            // _fgL.end();

            // let _fg0 = ::flame::start_guard("htp");
            let H_P = RistrettoPoint::hash_from_bytes::<Keccak512>(pk[j].compress().as_bytes());
            // _fg0.end();

            // compute R
            // let _fgR = ::flame::start_guard("R");
            // let sH = H_P * s_vec[j];
            // let cj_I = I * c_old;
            // let R = sH + cj_I;
            let R = RistrettoPoint::vartime_multiscalar_mul(&[s_vec[j], c_old], &[H_P, I]);
            // _fgR.end();

            // compute next c
            // let _fg1 = ::flame::start_guard("hts");
            tohash_vec[idxL..idxR].copy_from_slice(L.compress().as_bytes());
            tohash_vec[idxR..].copy_from_slice(R.compress().as_bytes());

            c_old = Scalar::hash_from_bytes::<Keccak512>(&tohash_vec); 
            j = (j + 1) % n;
            // _fg1.end();

            if j == 0 {
                c = c_old;
            }
        }

        // compute s_j
        s_vec[index] = alpha - (c_old * x);

        return LSAGSig {
            s_vec,
            c,
            I,
        };
    }

    pub fn ver_LSAG(
        &self,
        message: RistrettoPoint,
        pk: &[RistrettoPoint],
    ) -> Result<(), Errors> {

        // let _fg = ::flame::start_guard("ver LSAG");
        
        // ring size
        let n = pk.len();
        // let G = constants::RISTRETTO_BASEPOINT_POINT;
        assert!(n >= 2, "Error! Why ring signature if cols = 1!");
        assert!(self.s_vec.len() == n, "Bad rs.s_vec size.");

        // check if any element of s_vec or c is 0
        for i in 0..n {
            assert!(self.s_vec[i] != Scalar::zero(), "s_vec cannot have a 0 element!");
        }
        assert!(self.c != Scalar::zero(), "c cannot be 0!");

        // Construct a vector of EC points to hash
        let mut tohash_vec: Vec<u8> = Vec::new();
        for i in 0..n {
            tohash_vec.extend_from_slice(pk[i].compress().as_bytes());
        }
        tohash_vec.extend_from_slice(message.compress().as_bytes());
        tohash_vec.extend_from_slice(message.compress().as_bytes());
        tohash_vec.extend_from_slice(message.compress().as_bytes());

        // compute c_j's
        let mut j: usize = 0;
        let mut c_old = self.c;
        let idxL = (n+1)*32;
        let idxR = (n+2)*32;
        while j < n {

            // let _fgL = ::flame::start_guard("L");
            // compute L
            // let sG = G * self.s_vec[j];
            // let cpk_j = pk[j] * c_old;
            // let L = sG + cpk_j;
            let L = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c_old, &pk[j], &self.s_vec[j]);
            // _fgL.end();

            // compute Hash of pubkey
            // let _fg0 = ::flame::start_guard("htp");
            let H_P = RistrettoPoint::hash_from_bytes::<Keccak512>(pk[j].compress().as_bytes());
            // _fg0.end();

            // compute R
            // let _fgR = ::flame::start_guard("R");
            // let sH = H_P * self.s_vec[j];
            // let cj_I = self.I * c_old;
            // let R = sH + cj_I;
            let R = RistrettoPoint::vartime_multiscalar_mul(&[self.s_vec[j], c_old], &[H_P, self.I]);
            // _fgR.end();

            tohash_vec[idxL..idxR].copy_from_slice(L.compress().as_bytes());
            tohash_vec[idxR..].copy_from_slice(R.compress().as_bytes());
          
            // let _fg1 = ::flame::start_guard("hts");
            c_old = Scalar::hash_from_bytes::<Keccak512>(&tohash_vec); 
            // _fg1.end();
            
            j = j + 1;
        }

        if c_old == self.c {
            Ok(())
        } else {
            Err(MProveSigsError)
        }
    }

    pub fn initialize(n: usize) -> LSAGSig {
        // function to initialize a LSAGSig variable
        let s_vec = (0..n).map(|_| { Scalar::one() }).collect::<Vec<Scalar>>();
        let c = Scalar::one();
        let I = constants::RISTRETTO_BASEPOINT_POINT;

        return LSAGSig {
            s_vec,
            c,
            I,
        };
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Instant};

    pub fn test_RingSig(n: usize, idx: usize){
        
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let mut rng = rand::thread_rng();
        let msg = RistrettoPoint::random(&mut rng);

        let mut pk_vec: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let x = Scalar::random(&mut rng);
        pk_vec[idx] = G * x;

        // RingSig test
        println!("RingSig: (n={}, idx={})", n, idx);
        let start = Instant::now();
        let ring_sample = RingSig::gen_RingSig(msg, &pk_vec, x, idx); 
        let duration = start.elapsed();
        println!("gen time: {:?}", duration);

        let start = Instant::now();
        let result = ring_sample.ver_RingSig(msg, &pk_vec);
        let duration = start.elapsed();
        println!("ver time: {:?}", duration);
        
        assert!(result.is_ok());

        // LSAG test
        println!("LSAG: (n={}, idx={})", n, idx);
        let start = Instant::now();
        let LSAGring_sample = LSAGSig::gen_LSAG(msg, &pk_vec, x, idx);
        let duration = start.elapsed();
        println!("gen time: {:?}", duration);

        let start = Instant::now();
        let LSAGresult = LSAGring_sample.ver_LSAG(msg, &pk_vec);
        let duration = start.elapsed();
        println!("ver time: {:?}", duration);

        assert!(LSAGresult.is_ok());
    }

    #[test]
    pub fn sim_RingSig(){

        // RingSig: (n=1000, idx=100)
        // gen time: 3.008884509s
        // ver time: 2.973896138s
        // LSAG: (n=1000, idx=100)
        // gen time: 4.445220886s
        // ver time: 4.558239365s
        test_RingSig(1000, 100);
    }
}






