extern crate structopt;
extern crate mprove_ristretto;

use structopt::StructOpt;
use std::time::{Instant, Duration};
use mprove_ristretto::proofs::mprove::MProve;

#[derive(Debug, StructOpt)]
#[structopt(name = "mprove", about = "MProve proof generation simulator using Ristretto.")]
struct Opt {
  //#[structopt(short = "a", long = "anonsize")]
  anon_list_size: usize,
  //#[structopt(short = "o", long = "ownsize")]
  own_list_size: usize,
  #[structopt(short = "n", long = "numiter", default_value = "1")]
  num_iter: u32,
}

fn main() {
    // 
    // cargo run --release --bin mprove_bin 1000 100 -n 10
    //
    let opt = Opt::from_args();

    let num_iter = opt.num_iter;
    let mut mprove_proof;
    let mut gen_proof_start;
    let mut gen_proof_end;
    let mut ver_proof_start;
    let mut ver_proof_end;
    let mut total_gen_proof_duration = Duration::new(0, 0);
    let mut total_ver_proof_duration = Duration::new(0, 0);

    let (g, c_vec, p_vec, x_vec, e_vec) = MProve::gen_params(opt.anon_list_size, opt.own_list_size);

    let sim_start = Instant::now();

    for _i in 0..num_iter {        

        gen_proof_start = Instant::now();
        mprove_proof = MProve::prove(&g, &c_vec, &p_vec, &x_vec, &e_vec);
        gen_proof_end = Instant::now();
        total_gen_proof_duration += gen_proof_end.duration_since(gen_proof_start);
  
        ver_proof_start = Instant::now();
        assert!(mprove_proof.verify().is_ok());
        ver_proof_end = Instant::now();
        total_ver_proof_duration += ver_proof_end.duration_since(ver_proof_start);
      }
  
      let sim_end = Instant::now();
      println!("Total simulation time = {:?}", sim_end.duration_since(sim_start));
  
      println!("Options = {:?}", opt);
      println!("Average proof generation time = {:?}",
        total_gen_proof_duration.checked_div(num_iter).unwrap());
      println!("Average proof verification time = {:?}",
        total_ver_proof_duration.checked_div(num_iter).unwrap());

}


