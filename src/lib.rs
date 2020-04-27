/*

Copyright 2020 by Suyash Bagad, Saravanan Vijayakumaran

This file is part of mprove library
(<add a link to github>)

*/

// based on the paper: <link to paper>
#[macro_use]
extern crate serde_derive;
extern crate serde;

extern crate curv;
extern crate rand;
extern crate time;
extern crate flame;
extern crate curve25519_dalek;
extern crate sha2;


pub mod proofs;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    MProveSigsError,
    MProveError,
}
