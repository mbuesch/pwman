//! Pure Rust implementation of Argon2.
//! No external crates (only core and std).
//! No C dependencies.
//!
//! This program has been derived from:
//! argon2pure.py: Pure Python implementation of the Argon2 password hash
//! by Bas Westerbaan
//!
//! The MIT License (MIT)
//!
//! Copyright (c) 2026 Michael Büsch <m@bues.ch>
//! Copyright (c) 2016 Bas Westerbaan
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.

use core::array;
use std::thread;

const ARGON2D: u32 = 0;
const ARGON2I: u32 = 1;
const ARGON2ID: u32 = 2;

const ARGON2_VERSIONS: [u32; 2] = [0x10, 0x13];

const BLOCK: usize = 1024; // bytes per block
const QWORDS: usize = BLOCK / 8;

fn load_block(b: &[u8]) -> [u64; QWORDS] {
    array::from_fn(|i| u64::from_le_bytes(b[(i * 8)..((i * 8) + 8)].try_into().unwrap()))
}

fn store_block(v: &[u64; QWORDS]) -> [u8; BLOCK] {
    array::from_fn(|i| (v[i / 8] >> ((i % 8) * 8)) as u8)
}

fn xor1024(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let a = load_block(a);
    let b = load_block(b);
    store_block(&array::from_fn(|i| a[i] ^ b[i]))
}

// ---------------------------------------------------------------------------
// Argon2 compression function G and permutation P
// ---------------------------------------------------------------------------

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    let f = |x: u64, y: u64| -> u64 {
        x.wrapping_add(y).wrapping_add(
            2u64.wrapping_mul(x & 0xffff_ffff)
                .wrapping_mul(y & 0xffff_ffff),
        )
    };
    let mut va = v[a];
    let mut vb = v[b];
    let mut vc = v[c];
    let mut vd = v[d];
    va = f(va, vb);
    vd = (vd ^ va).rotate_right(32);
    vc = f(vc, vd);
    vb = (vb ^ vc).rotate_right(24);
    va = f(va, vb);
    vd = (vd ^ va).rotate_right(16);
    vc = f(vc, vd);
    vb = (vb ^ vc).rotate_right(63);
    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
}

/// P: Modified Blake2 permutation
fn permute_p(s: &[u64; 16]) -> [u64; 16] {
    let mut v = *s;
    g(&mut v, 0, 4, 8, 12);
    g(&mut v, 1, 5, 9, 13);
    g(&mut v, 2, 6, 10, 14);
    g(&mut v, 3, 7, 11, 15);
    g(&mut v, 0, 5, 10, 15);
    g(&mut v, 1, 6, 11, 12);
    g(&mut v, 2, 7, 8, 13);
    g(&mut v, 3, 4, 9, 14);
    v
}

/// G: Argon2 compression function.
fn compress(x: &[u8; BLOCK], y: &[u8; BLOCK]) -> [u8; BLOCK] {
    let xv = load_block(x);
    let yv = load_block(y);
    let r: [u64; QWORDS] = array::from_fn(|i| xv[i] ^ yv[i]);

    // Row rounds: 8 rows of 16 u64 (128 bytes) each.
    let mut q = [0u64; QWORDS];
    for i in 0..8 {
        let slice: [u64; 16] = array::from_fn(|j| r[i * 16 + j]);
        let out = permute_p(&slice);
        q[i * 16..i * 16 + 16].copy_from_slice(&out);
    }

    // Column rounds: P is applied to the 8 "columns" (Q[i], Q[i+8], ...,
    // Q[i+56]) -- matching the reference implementation's register layout.
    let mut z = [0u64; QWORDS];
    for i in 0..8 {
        let slice: [u64; 16] = std::array::from_fn(|j| q[16 * (j / 2) + (2 * i) + (j % 2)]);
        let out = permute_p(&slice);
        for j in 0..8 {
            z[16 * j + 2 * i] = out[2 * j];
            z[16 * j + 2 * i + 1] = out[2 * j + 1];
        }
    }

    store_block(&array::from_fn(|i| z[i] ^ r[i]))
}

// ---------------------------------------------------------------------------
// Blake2b
// ---------------------------------------------------------------------------

const B2_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const B2_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    digest_len: usize,
    n: u128,
}

pub struct Blake2bDigest {
    digest: [u8; 64],
    digest_len: usize,
}

impl Blake2bDigest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.digest[..self.digest_len]
    }

    pub fn into_array(self) -> [u8; 64] {
        self.digest
    }
}

impl Blake2b {
    pub fn new(digest_len: usize) -> Blake2b {
        let h: [u64; 8] = array::from_fn(|i| {
            if i == 0 {
                B2_IV[i] ^ (0x0000_0000_0101_0000u64 | (digest_len as u64))
            } else {
                B2_IV[i]
            }
        });
        Blake2b {
            h,
            buf: [0u8; 128],
            buf_len: 0,
            digest_len,
            n: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let l = data.len();
        if self.buf_len + l <= 128 {
            self.buf[self.buf_len..self.buf_len + l].copy_from_slice(data);
            self.buf_len += l;
            return;
        }

        let take = 128 - self.buf_len;
        let block: [u8; 128] = array::from_fn(|i| {
            if i < self.buf_len {
                self.buf[i]
            } else {
                data[i - self.buf_len]
            }
        });
        self.compress(&block, 128);
        let mut i = take;
        while l - i > 128 {
            self.compress(&data[i..i + 128], 128);
            i += 128;
        }

        self.buf_len = l - i;
        self.buf[..self.buf_len].copy_from_slice(&data[i..]);
    }

    pub fn finalize(mut self) -> Blake2bDigest {
        // finalization flag f[0] = all ones
        let buf: [u8; 128] = self.buf.clone();
        self.compress_final(&buf, self.buf_len);
        Blake2bDigest {
            digest: array::from_fn(|i| {
                if i < self.digest_len {
                    (self.h[i / 8] >> ((i % 8) * 8)) as u8
                } else {
                    0
                }
            }),
            digest_len: self.digest_len,
        }
    }

    fn compress(&mut self, block: &[u8], n_data: usize) {
        self.compress_inner(block, n_data, false);
    }

    fn compress_final(&mut self, block: &[u8], n_data: usize) {
        self.compress_inner(block, n_data, true);
    }

    fn compress_inner(&mut self, block: &[u8], n_data: usize, last: bool) {
        self.n += n_data as u128;
        let t0 = self.n as u64;
        let t1 = (self.n >> 64) as u64;
        let m: [u64; 16] = array::from_fn(|i| {
            u64::from_le_bytes(block[(i * 8)..((i * 8) + 8)].try_into().unwrap())
        });
        let mut v: [u64; 16] = array::from_fn(|i| if i < 8 { self.h[i] } else { B2_IV[i - 8] });
        v[12] ^= t0;
        v[13] ^= t1;
        if last {
            v[14] ^= 0xffff_ffff_ffff_ffffu64;
        }
        for r in 0..12 {
            b2_g(&mut v, &m, r, 0, 0, 4, 8, 12);
            b2_g(&mut v, &m, r, 1, 1, 5, 9, 13);
            b2_g(&mut v, &m, r, 2, 2, 6, 10, 14);
            b2_g(&mut v, &m, r, 3, 3, 7, 11, 15);
            b2_g(&mut v, &m, r, 4, 0, 5, 10, 15);
            b2_g(&mut v, &m, r, 5, 1, 6, 11, 12);
            b2_g(&mut v, &m, r, 6, 2, 7, 8, 13);
            b2_g(&mut v, &m, r, 7, 3, 4, 9, 14);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

fn b2_g(
    v: &mut [u64; 16],
    m: &[u64; 16],
    r: usize,
    i: usize,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
) {
    let mut va = v[a];
    let mut vb = v[b];
    let mut vc = v[c];
    let mut vd = v[d];
    va = va.wrapping_add(vb).wrapping_add(m[B2_SIGMA[r][2 * i]]);
    vd = (vd ^ va).rotate_right(32);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(24);
    va = va.wrapping_add(vb).wrapping_add(m[B2_SIGMA[r][2 * i + 1]]);
    vd = (vd ^ va).rotate_right(16);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(63);
    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
}

fn blake2b(data: &[u8], digest_len: usize) -> Blake2bDigest {
    let mut b = Blake2b::new(digest_len);
    b.update(data);
    b.finalize()
}

// ---------------------------------------------------------------------------
// H': variable length hash based on Blake2b
// ---------------------------------------------------------------------------

fn h_prime(x: &[u8], tag_length: usize) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(4 + x.len());
    prefix.extend_from_slice(&(tag_length as u32).to_le_bytes());
    prefix.extend_from_slice(x);

    if tag_length <= 64 {
        return blake2b(&prefix, tag_length).as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(tag_length);
    let mut v = blake2b(&prefix, 64); // V_1
    out.extend_from_slice(&v.as_bytes()[..32]);
    let mut todo = tag_length - 32;
    while todo > 64 {
        v = blake2b(v.as_bytes(), 64); // V_2 .. V_r
        out.extend_from_slice(&v.as_bytes()[..32]);
        todo -= 32;
    }
    out.extend_from_slice(&blake2b(v.as_bytes(), todo).as_bytes()); // V_{r+1}
    out
}

// ---------------------------------------------------------------------------
// Argon2 core
// ---------------------------------------------------------------------------

struct Params {
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    type_code: u32,
    version: u32,
    h0: [u8; 64],
}

fn initial_hash(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    parallelism: u32,
    tag_length: u32,
    memory_cost: u32,
    time_cost: u32,
    version: u32,
    type_code: u32,
) -> [u8; 64] {
    let mut h = Blake2b::new(64);
    h.update(&parallelism.to_le_bytes());
    h.update(&tag_length.to_le_bytes());
    h.update(&memory_cost.to_le_bytes());
    h.update(&time_cost.to_le_bytes());
    h.update(&version.to_le_bytes());
    h.update(&type_code.to_le_bytes());
    let mut update_w_len = |data: &[u8]| {
        h.update(&(data.len() as u32).to_le_bytes());
        h.update(data);
    };
    update_w_len(password);
    update_w_len(salt);
    update_w_len(secret);
    update_w_len(associated_data);
    h.finalize().into_array()
}

/// Read-only view of one lane's memory outside of the currently-filled segment.
struct LaneView<'a> {
    start: usize,              // first column of the currently-filled segment
    end: usize,                // one past the last column of the currently-filled segment
    before: &'a [[u8; BLOCK]], // columns 0..start
    after: &'a [[u8; BLOCK]],  // columns end..q
}

impl LaneView<'_> {
    /// Read a block outside of the currently-filled segment.
    fn get(&self, col: usize) -> &[u8; BLOCK] {
        if col < self.start {
            &self.before[col]
        } else if col >= self.end {
            &self.after[col - self.end]
        } else {
            unreachable!()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fill_segment(
    cur: &mut [[u8; BLOCK]],
    views: &[LaneView],
    t: u32,
    segment: u32,
    i: usize,
    p: &Params,
    q: usize,
    segment_length: usize,
) {
    let parallelism = p.parallelism as usize;
    let start = (segment as usize) * segment_length;
    let end = start + segment_length;
    let data_independent =
        p.type_code == ARGON2I || (p.type_code == ARGON2ID && t == 0 && segment <= 1);

    let mut pseudo_rands: Vec<(u32, u32)> = vec![];
    if data_independent {
        let mut ctr: u64 = 0;
        pseudo_rands.reserve(segment_length);
        while pseudo_rands.len() < segment_length {
            ctr += 1;
            let vals: [u64; 7] = [
                t.into(),
                i as u64,
                segment.into(),
                p.memory_cost.into(), // m_prime, see below (fixed after)
                p.time_cost.into(),
                p.type_code.into(),
                ctr,
            ];
            let input: [u8; BLOCK] = array::from_fn(|i| {
                let j = i / 8;
                if j < vals.len() {
                    (vals[j] >> ((i % 8) * 8)) as u8
                } else {
                    0
                }
            });
            let zero = [0u8; BLOCK];
            let address_block = compress(&zero, &compress(&zero, &input));
            for addr in address_block.chunks(8) {
                let j1 = u32::from_le_bytes([addr[0], addr[1], addr[2], addr[3]]);
                let j2 = u32::from_le_bytes([addr[4], addr[5], addr[6], addr[7]]);
                pseudo_rands.push((j1, j2));
            }
        }
    }

    for index in 0..segment_length {
        let j = start + index;
        if t == 0 && j < 2 {
            let inp: [u8; 72] = {
                let j = (j as u32).to_le_bytes();
                let i = (i as u32).to_le_bytes();
                array::from_fn(|k| {
                    if k < 64 {
                        p.h0[k]
                    } else if k >= 68 {
                        i[k - 68]
                    } else {
                        j[k - 64]
                    }
                })
            };
            cur[index].copy_from_slice(&h_prime(&inp, BLOCK));
            continue;
        }

        // Previous block of this lane. For index == 0 it is the last block of
        // the previous segment (or of the previous pass); otherwise it is
        // inside of the current segment.
        let prev: &[u8; BLOCK] = if index == 0 {
            views[i].get((j + q - 1) % q)
        } else {
            &cur[index - 1]
        };

        let (j1, j2) = if data_independent {
            pseudo_rands[index]
        } else {
            let j1 = u32::from_le_bytes([prev[0], prev[1], prev[2], prev[3]]);
            let j2 = u32::from_le_bytes([prev[4], prev[5], prev[6], prev[7]]);
            (j1, j2)
        };

        let i_prime = if t == 0 && segment == 0 {
            i
        } else {
            (j2 as usize) % parallelism
        };

        let ref_area_size: usize = if t == 0 {
            if segment == 0 || i == i_prime {
                j - 1
            } else if index == 0 {
                (segment as usize) * segment_length - 1
            } else {
                (segment as usize) * segment_length
            }
        } else if i == i_prime {
            q - segment_length + index - 1
        } else if index == 0 {
            q - segment_length - 1
        } else {
            q - segment_length
        };

        let rel_pos = ((j1 as u64) * (j1 as u64)) >> 32;
        let rel_pos = (ref_area_size as u64) - 1 - (((ref_area_size as u64) * rel_pos) >> 32);
        let mut start_pos: usize = 0;
        if t != 0 && segment != 3 {
            start_pos = ((segment as usize) + 1) * segment_length;
        }
        let j_prime = ((start_pos as u64 + rel_pos) % (q as u64)) as usize;

        // A reference never points into another lane's current segment. But
        // it may point into the already computed part of this lane's current
        // segment, which is read from `cur`.
        let reference: &[u8; BLOCK] = if i_prime == i && (start..end).contains(&j_prime) {
            &cur[j_prime - start]
        } else {
            views[i_prime].get(j_prime)
        };

        let mut new_block = compress(prev, reference);
        if t != 0 && p.version == 0x13 {
            new_block = xor1024(&cur[index], &new_block);
        }
        cur[index] = new_block;
    }
}

/// Compute the Argon2.
pub fn argon2(
    password: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    tag_length: u32,
    secret: &[u8],
    associated_data: &[u8],
    type_code: u32,
    version: u32,
) -> Result<Vec<u8>, &'static str> {
    if parallelism == 0 || parallelism > u32::MAX / 8 {
        return Err("parallelism too small or too large");
    }
    if time_cost == 0 {
        return Err("time_cost must be positive");
    }
    if memory_cost < 8 * parallelism {
        return Err("memory_cost must be >=8 times #lanes");
    }
    if ![ARGON2D, ARGON2I, ARGON2ID].contains(&type_code) {
        return Err("type_code not supported");
    }
    if !ARGON2_VERSIONS.contains(&version) {
        return Err("version not supported");
    }
    if tag_length == 0 {
        return Err("tag_length must be positive");
    }

    let p_lanes = parallelism as usize;
    let m_prime = (memory_cost / (4 * parallelism)) * (4 * parallelism);
    let q = (m_prime / parallelism) as usize; // lane length
    let segment_length = q / 4;

    let h0 = initial_hash(
        password,
        salt,
        secret,
        associated_data,
        parallelism,
        tag_length,
        memory_cost,
        time_cost,
        version,
        type_code,
    );

    let params = Params {
        time_cost,
        memory_cost: m_prime,
        parallelism,
        type_code,
        version,
        h0,
    };

    // Per-lane memory: each lane gets its own allocation of q blocks.
    let mut mem: Vec<Vec<[u8; BLOCK]>> = (0..p_lanes).map(|_| vec![[0u8; BLOCK]; q]).collect();

    for t in 0..time_cost {
        for segment in 0..4u32 {
            let start = segment as usize * segment_length;

            // Split every lane into the blocks before the current segment,
            // the current segment itself and the blocks after it.
            // A lane only writes to its own current segment and only reads
            // other lanes' blocks outside of their current segment, so each
            // thread can be given its lane's current segment plus read-only
            // views of the rest. No memory copying is needed.
            let mut curs: Vec<&mut [[u8; BLOCK]]> = Vec::with_capacity(p_lanes);
            let mut views: Vec<LaneView> = Vec::with_capacity(p_lanes);
            for lane_mem in mem.iter_mut() {
                let (before, rest) = lane_mem.split_at_mut(start);
                let (cur, after) = rest.split_at_mut(segment_length);
                views.push(LaneView {
                    start,
                    end: start + segment_length,
                    before,
                    after,
                });
                curs.push(cur);
            }

            thread::scope(|thread_scope| {
                let params = &params;
                let views = &views;
                let mut handles = Vec::with_capacity(p_lanes);
                for (lane, cur) in curs.into_iter().enumerate() {
                    handles.push(thread_scope.spawn(move || {
                        fill_segment(cur, views, t, segment, lane, params, q, segment_length);
                    }));
                }
                for handle in handles {
                    handle.join().expect("worker thread panicked");
                }
            });
        }
    }

    let mut b_final = [0u8; BLOCK];
    for lane_mem in &mem {
        b_final = xor1024(&b_final, &lane_mem[q - 1]);
    }

    Ok(h_prime(&b_final, tag_length as usize))
}

// ===========================================================================
// CPython module
// ===========================================================================
#[allow(non_camel_case_types)]
mod pyffi {
    use super::*;
    use core::{
        ffi::{c_char, c_int, c_long, c_uint, c_void},
        ptr::{null, null_mut},
        slice,
    };

    const METH_VARARGS: c_int = 0x0001;
    const METH_KEYWORDS: c_int = 0x0002;
    const PYTHON_API_VERSION: c_int = 1013;

    pub enum PyObject {}

    #[repr(C)]
    #[derive(Default)]
    pub struct PyMethodDef {
        pub ml_name: *const c_char,
        pub ml_meth: Option<
            unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject,
        >,
        pub ml_flags: c_int,
        pub ml_doc: *const c_char,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct PyModuleDef_Base {
        pub ob_refcnt: isize,
        pub ob_type: *mut c_void,
        pub m_init: *mut c_void,
        pub m_index: isize,
        pub m_copy: *mut c_void,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct PyModuleDef {
        pub m_base: PyModuleDef_Base,
        pub m_name: *const c_char,
        pub m_doc: *const c_char,
        pub m_size: isize,
        pub m_methods: *const PyMethodDef,
        pub m_slots: *mut c_void,
        pub m_traverse: *mut c_void,
        pub m_clear: *mut c_void,
        pub m_free: *mut c_void,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct Py_buffer {
        pub buf: *mut c_void,
        pub obj: *mut PyObject,
        pub len: isize,
        pub itemsize: isize,
        pub readonly: c_int,
        pub ndim: c_int,
        pub format: *mut c_char,
        pub shape: *mut isize,
        pub strides: *mut isize,
        pub suboffsets: *mut isize,
        pub internal: *mut c_void,
    }

    impl From<&Py_buffer> for &[u8] {
        fn from(b: &Py_buffer) -> Self {
            if b.buf.is_null() || b.len <= 0 {
                &[]
            } else {
                unsafe { slice::from_raw_parts(b.buf.cast(), b.len as usize) }
            }
        }
    }

    impl From<Py_buffer> for Vec<u8> {
        fn from(mut b: Py_buffer) -> Self {
            let bytes = Into::<&[u8]>::into(&b).to_vec();
            if !b.buf.is_null() {
                unsafe { PyBuffer_Release(&mut b) };
            }
            bytes
        }
    }

    unsafe extern "C" {
        pub fn PyModule_Create2(module: *mut PyModuleDef, apiver: c_int) -> *mut PyObject;
        pub fn PyArg_ParseTupleAndKeywords(
            args: *mut PyObject,
            kwargs: *mut PyObject,
            fmt: *const c_char,
            keywords: *mut *mut c_char,
            ...
        ) -> c_int;
        pub fn PyBytes_FromStringAndSize(v: *const c_char, len: isize) -> *mut PyObject;
        pub fn PyErr_SetString(exc: *mut PyObject, msg: *const c_char);
        pub static mut PyExc_ValueError: *mut PyObject;
        pub fn PyBuffer_Release(view: *mut Py_buffer);
        pub fn PyModule_AddIntConstant(
            module: *mut PyObject,
            name: *const c_char,
            value: c_long,
        ) -> c_int;
    }

    unsafe extern "C" fn py_argon2(
        _self: *mut PyObject,
        args: *mut PyObject,
        kwargs: *mut PyObject,
    ) -> *mut PyObject {
        let mut password = Py_buffer::default();
        let mut salt = Py_buffer::default();
        let mut secret = Py_buffer::default();
        let mut ad = Py_buffer::default();
        let mut time_cost: c_uint = 0;
        let mut memory_cost: c_uint = 0;
        let mut parallelism: c_uint = 0;
        let mut tag_length: c_uint = 32;
        let mut type_code: c_uint = ARGON2I;
        let mut threads: *mut PyObject = null_mut();
        let mut version: c_uint = 0x13;
        let mut use_threads: c_int = 0;

        let kwlist: [*const c_char; 13] = [
            b"password\0".as_ptr().cast(),
            b"salt\0".as_ptr().cast(),
            b"time_cost\0".as_ptr().cast(),
            b"memory_cost\0".as_ptr().cast(),
            b"parallelism\0".as_ptr().cast(),
            b"tag_length\0".as_ptr().cast(),
            b"secret\0".as_ptr().cast(),
            b"associated_data\0".as_ptr().cast(),
            b"type_code\0".as_ptr().cast(),
            b"threads\0".as_ptr().cast(),
            b"version\0".as_ptr().cast(),
            b"use_threads\0".as_ptr().cast(),
            null(),
        ];

        if unsafe {
            PyArg_ParseTupleAndKeywords(
                args,
                kwargs,
                b"y*y*III|Iy*y*IOIp:argon2\0".as_ptr().cast(),
                kwlist.as_ptr() as *mut *mut c_char,
                &mut password,
                &mut salt,
                &mut time_cost,
                &mut memory_cost,
                &mut parallelism,
                &mut tag_length,
                &mut secret,
                &mut ad,
                &mut type_code,
                &mut threads,
                &mut version,
                &mut use_threads,
            )
        } == 0
        {
            return null_mut();
        }

        let pw: Vec<u8> = password.into();
        let sa: Vec<u8> = salt.into();
        let se: Vec<u8> = secret.into();
        let adata: Vec<u8> = ad.into();

        match argon2(
            &pw,
            &sa,
            time_cost as u32,
            memory_cost as u32,
            parallelism as u32,
            tag_length as u32,
            &se,
            &adata,
            type_code as u32,
            version as u32,
        ) {
            Ok(tag) => unsafe {
                PyBytes_FromStringAndSize(tag.as_ptr().cast(), tag.len() as isize)
            },
            Err(e) => {
                let mut msg = e.as_bytes().to_vec();
                msg.push(0); // nul-terminate
                unsafe { PyErr_SetString(PyExc_ValueError, msg.as_ptr().cast()) };
                null_mut()
            }
        }
    }

    // ---- Module definition ----------------------------------------------

    // These raw-pointer-bearing structs are only ever touched from the
    // Python interpreter side.
    unsafe impl Sync for PyMethodDef {}
    unsafe impl Sync for PyModuleDef {}

    static METHODS: [PyMethodDef; 2] = [
        PyMethodDef {
            ml_name: b"argon2\0".as_ptr() as *const c_char,
            ml_meth: Some(py_argon2),
            ml_flags: METH_VARARGS | METH_KEYWORDS,
            ml_doc: b"argon2(password, salt, time_cost, memory_cost, parallelism, tag_length=32, secret=b'', associated_data=b'', type_code=1, threads=None, version=0x13, use_threads=False) -> bytes\0"
                .as_ptr().cast(),
        },
        PyMethodDef {
            ml_name: null(),
            ml_meth: None,
            ml_flags: 0,
            ml_doc: null(),
        },
    ];

    static mut MODULE: PyModuleDef = PyModuleDef {
        m_base: PyModuleDef_Base {
            ob_refcnt: 1, // immortality not needed; CPython fixes this up
            ob_type: null_mut(),
            m_init: null_mut(),
            m_index: 0,
            m_copy: null_mut(),
        },
        m_name: b"argon2purers\0".as_ptr().cast(),
        m_doc: b"Rust Argon2\0".as_ptr().cast(),
        m_size: -1,
        m_methods: METHODS.as_ptr(),
        m_slots: null_mut(),
        m_traverse: null_mut(),
        m_clear: null_mut(),
        m_free: null_mut(),
    };

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn PyInit_argon2purers() -> *mut PyObject {
        let m = unsafe { PyModule_Create2(&raw mut MODULE, PYTHON_API_VERSION) };
        if !m.is_null() {
            unsafe {
                PyModule_AddIntConstant(m, b"ARGON2D\0".as_ptr().cast(), ARGON2D as c_long);
                PyModule_AddIntConstant(m, b"ARGON2I\0".as_ptr().cast(), ARGON2I as c_long);
                PyModule_AddIntConstant(m, b"ARGON2ID\0".as_ptr().cast(), ARGON2ID as c_long);
            }
        }
        m
    }
}
