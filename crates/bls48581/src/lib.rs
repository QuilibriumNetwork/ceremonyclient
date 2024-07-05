/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::new_without_default)]
pub mod bls48581;
pub mod bls;
pub mod arch;
pub mod rand;
pub mod hmac;
pub mod hash256;
pub mod hash384;
pub mod hash512;
pub mod sha3;

use std::error::Error;
use bls48581::big;
use bls48581::ecp;
use bls48581::ecp8;
use bls48581::rom;
use bls48581::pair8;

uniffi::include_scaffolding!("lib");

fn recurse_fft(
    values: &[big::BIG],
    offset: u64,
    stride: u64,
    roots_stride: u64,
    out: &mut [big::BIG],
    fft_width: u64,
    inverse: bool,
) {
  let M = &big::BIG::new_ints(&rom::CURVE_ORDER);
  let roots = if inverse {
    &bls::singleton().ReverseRootsOfUnityBLS48581[&fft_width]
  } else {
    &bls::singleton().RootsOfUnityBLS48581[&fft_width]
  };

  if out.len() == 1 {
    // optimization: we're working in bls48-581, the first roots of unity
    // value is always 1 no matter the fft width, so we can skip the
    // multiplication:
    out[0] = values[offset as usize].clone();
    return;
  }

  let half = (out.len() as u64) >> 1;

  // slide to the left
  recurse_fft(
    values,
    offset,
    stride << 1,
    roots_stride << 1,
    &mut out[..half as usize],
    fft_width,
    inverse,
  );

  // slide to the right
  recurse_fft(
    values,
    offset + stride,
    stride << 1,
    roots_stride << 1,
    &mut out[half as usize..],
    fft_width,
    inverse,
  );

  // cha cha now, y'all
  for i in 0..half {
    let mul = big::BIG::modmul(
      &out[(i + half) as usize],
      &roots[(i * roots_stride) as usize],
      &big::BIG::new_ints(&rom::CURVE_ORDER),
    );
    let mul_add = big::BIG::modadd(
      &out[i as usize],
      &mul,
      &big::BIG::new_ints(&rom::CURVE_ORDER),
    );
    out[(i + half) as usize] = big::BIG::modadd(
      &out[i as usize],
      &big::BIG::modneg(&mul, &big::BIG::new_ints(&rom::CURVE_ORDER)),
      &big::BIG::new_ints(&rom::CURVE_ORDER),
    );
    out[i as usize] = mul_add;
  }
}

pub fn fft(
  values: &[big::BIG],
  fft_width: u64,
  inverse: bool,
) -> Result<Vec<big::BIG>, String> {
  let mut width = values.len() as u64;
  if width > fft_width {
    return Err("invalid width of values".into());
  }

  if width & (width - 1) != 0 {
    width = nearest_power_of_two(width);
  }

  // We make a copy so we can mutate it during the work.
  let mut working_values = vec![big::BIG::new(); width as usize];
  for i in 0..values.len() {
    working_values[i] = values[i].clone();
  }
  for i in values.len()..width as usize {
    working_values[i] = big::BIG::new();
  }

  let mut out = vec![big::BIG::new(); width as usize];
  let stride = fft_width / width;

  if inverse {
    let mut inv_len = big::BIG::new_int(width as isize);
    inv_len.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));

    recurse_fft(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    for i in 0..out.len() {
      out[i] = big::BIG::modmul(&out[i], &inv_len, &big::BIG::new_ints(&rom::CURVE_ORDER));
    }

    Ok(out)
  } else {
    recurse_fft(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    Ok(out)
  }
}

fn recurse_fft_g1(
  values: &[ecp::ECP],
  offset: u64,
  stride: u64,
  roots_stride: u64,
  out: &mut [ecp::ECP],
  fft_width: u64,
  inverse: bool,
) {
  let roots = if inverse {
    &bls::singleton().ReverseRootsOfUnityBLS48581[&fft_width]
  } else {
    &bls::singleton().RootsOfUnityBLS48581[&fft_width]
  };

  if out.len() == 1 {
    out[0] = values[offset as usize].clone();
    return;
  }

  let half = (out.len() as u64) >> 1;

  // slide to the left
  recurse_fft_g1(
    values,
    offset,
    stride << 1,
    roots_stride << 1,
    &mut out[..half as usize],
    fft_width,
    inverse,
  );

  // slide to the right
  recurse_fft_g1(
    values,
    offset + stride,
    stride << 1,
    roots_stride << 1,
    &mut out[half as usize..],
    fft_width,
    inverse,
  );

  // cha cha now, y'all
  for i in 0..half {
    let mul = out[(i + half) as usize].clone().mul(
      &roots[(i * roots_stride) as usize].clone(),
    );
    let mut mul_add = out[i as usize].clone();
    mul_add.add(&mul.clone());
    out[(i + half) as usize] = out[i as usize].clone();
    out[(i + half) as usize].sub(&mul);
    out[i as usize] = mul_add;
  }
}

pub fn fft_g1(
  values: &[ecp::ECP],
  fft_width: u64,
  inverse: bool,
) -> Result<Vec<ecp::ECP>, String> {
  let mut width = values.len() as u64;
  if width > fft_width {
    return Err("invalid width of values".into());
  }

  if width & (width - 1) != 0 {
    width = nearest_power_of_two(width);
  }

  let mut working_values = vec![ecp::ECP::new(); width as usize];
  for i in 0..values.len() {
    working_values[i] = values[i].clone();
  }
  for i in values.len()..width as usize {
    working_values[i] = ecp::ECP::generator();
  }

  let mut out = vec![ecp::ECP::new(); width as usize];
  let stride = fft_width / width;

  if inverse {
    let mut inv_len = big::BIG::new_int(width as isize);
    inv_len.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));

    recurse_fft_g1(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    for i in 0..out.len() {
      out[i] = out[i].clone().mul(&inv_len);
    }

    Ok(out)
  } else {
    recurse_fft_g1(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    Ok(out)
  }
}

fn nearest_power_of_two(number: u64) -> u64 {
  let mut power = 1;
  while number > power {
    power <<= 1;
  }
  power
}

fn bytes_to_polynomial(
  bytes: &[u8],
) -> Vec<big::BIG> {
  let size = bytes.len() / 64;
  let trunc_last = bytes.len() % 64 > 0;

  let mut poly = Vec::with_capacity(size + (if trunc_last { 1 } else { 0 }));

  for i in 0..size {
    let scalar = big::BIG::frombytes(&bytes[i * 64..(i + 1) * 64]);
    poly.push(scalar);
  }

  if trunc_last {
    let scalar = big::BIG::frombytes(&bytes[size * 64..]);
    poly.push(scalar);
  }

  return poly;
}

pub fn point_linear_combination(
  points: &[ecp::ECP],
  scalars: &Vec<big::BIG>,
) -> Result<ecp::ECP, Box<dyn Error>> {
  if points.len() != scalars.len() {
    return Err(format!(
      "length mismatch between arguments, points: {}, scalars: {}",
      points.len(),
      scalars.len(),
    ).into());
  }

  let result = ecp::ECP::muln(points.len(), points, scalars.as_slice());

  Ok(result)
}

fn verify(
  commitment: &ecp::ECP,
  z: &big::BIG,
  y: &big::BIG,
  proof: &ecp::ECP,
) -> bool {
  let z2 = ecp8::ECP8::generator().mul(z);
  let y1 = ecp::ECP::generator().mul(y);
  let mut xz = bls::singleton().CeremonyBLS48581G2[1].clone();
  xz.sub(&z2);
  let mut cy = commitment.clone();
  cy.sub(&y1);
  cy.neg();

  let mut r = pair8::initmp();

  pair8::another(&mut r, &xz, &proof);
  pair8::another(&mut r, &ecp8::ECP8::generator(), &cy);
  let mut v = pair8::miller(&mut r);
  v = pair8::fexp(&v);
  return v.isunity();
}

pub fn commit_raw(
  data: &[u8],
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = bytes_to_polynomial(data);
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }
  match point_linear_combination(
		&bls::singleton().FFTBLS48581[&poly_size],
		&poly,
	) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      return b.to_vec();
    }
    Err(_e) => {
      return [].to_vec();
    }
  }
}

pub fn prove_raw(
  data: &[u8],
  index: u64,
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = bytes_to_polynomial(data);
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }

  let z = bls::singleton().RootsOfUnityBLS48581[&poly_size][index as usize];

  match fft(
    &poly,
    poly_size,
    true,
  ) {
    Ok(eval_poly) => {
      let mut subz = big::BIG::new_int(0);
      subz = big::BIG::modadd(&subz, &big::BIG::modneg(&z, &big::BIG::new_ints(&rom::CURVE_ORDER)), &big::BIG::new_ints(&rom::CURVE_ORDER));
      let mut subzinv = subz.clone();
      subzinv.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));
      let mut o = big::BIG::new_int(1);
      let mut oinv = o.clone();
      oinv.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));
      let divisors: Vec<big::BIG> = vec![
        subz,
        o
      ];
      let invdivisors: Vec<big::BIG> = vec![
        subzinv,
        oinv
      ];
    
      let mut a: Vec<big::BIG> = eval_poly.iter().map(|x| x.clone()).collect();
    
      // Adapted from Feist's amortized proofs:
      let mut a_pos = a.len() - 1;
      let b_pos = divisors.len() - 1;
      let mut diff = a_pos as isize - b_pos as isize;
      let mut out: Vec<big::BIG> = vec![big::BIG::new(); (diff + 1) as usize];
      while diff >= 0 {
        out[diff as usize] = a[a_pos].clone();
        out[diff as usize] = big::BIG::modmul(&out[diff as usize], &invdivisors[b_pos], &big::BIG::new_ints(&rom::CURVE_ORDER));
        for i in (0..=b_pos).rev() {
          let den = &out[diff as usize].clone();
          a[diff as usize + i] = a[diff as usize + i].clone();
          a[diff as usize + i] = big::BIG::modadd(
            &a[diff as usize + i],
            &big::BIG::modneg(
              &big::BIG::modmul(&den, &divisors[i], &big::BIG::new_ints(&rom::CURVE_ORDER)),
              &big::BIG::new_ints(&rom::CURVE_ORDER)
            ),
            &big::BIG::new_ints(&rom::CURVE_ORDER)
          );
        }
        let mut b = [0u8;73];
        out[diff as usize].tobytes(&mut b);

        a_pos -= 1;
        diff -= 1;
      }
    
      match point_linear_combination(
        &bls::singleton().CeremonyBLS48581G1[..(poly_size as usize - 1)],
        &out,
      ) {
        Ok(proof) => {
          let mut b = [0u8; 74];
          proof.tobytes(&mut b, true);
          return b.to_vec();
        }
        Err(_e) => {
          return [].to_vec();
        }
      }
    },
    Err(_e) => {
      return [].to_vec();
    }
  }
}

pub fn verify_raw(
  data: &[u8],
  commit: &[u8],
  index: u64,
  proof: &[u8],
  poly_size: u64,
) -> bool {
  let z = bls::singleton().RootsOfUnityBLS48581[&poly_size][index as usize];

  let y = big::BIG::frombytes(data);

  let c = ecp::ECP::frombytes(commit);
  let p = ecp::ECP::frombytes(proof);

  return verify(
    &c,
    &z,
    &y,
    &p,
  );
}

pub fn init() {
  bls::singleton();
}

#[cfg(test)]
mod tests {
    use ecp::ECP;

    use super::*;

    #[test]
    fn fft_matches_fft_g1_when_raised() {
      init();
      let mut rand = rand::RAND::new();
      let mut v = vec![big::BIG::new(); 16];
      let mut vp = vec![ECP::new(); 16];
      for i in 0..16 {
        v[i] = big::BIG::random(&mut rand);
        vp[i] = ECP::generator().mul(&v[i]);
      }
      let scalars = fft(v.as_slice(), 16, false).unwrap();
      let points = fft_g1(vp.as_slice(), 16, false).unwrap();
      for (i, s) in scalars.iter().enumerate() {
        let sp = ECP::generator().mul(&s);
        assert!(points[i].equals(&sp));
      }
    }
}