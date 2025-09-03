use super::hash::hash_pair;

pub fn compute_header_root(leaves: [[u8; 32]; 5]) -> [u8; 32] {
    // Level 1
    let h0 = hash_pair(leaves[0], leaves[1]);
    let h1 = hash_pair(leaves[2], leaves[3]);
    let h2 = leaves[4];

    // Level 2
    let h3 = hash_pair(h0, h1);

    // Root
    let root = hash_pair(h3, h2);

    root
}