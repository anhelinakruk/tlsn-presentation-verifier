use std::hash::blake3;

pub mod verify_signature;

pub fn compute_merkle_root<let N: u32>(
    leaf: [u8; 32],
    index: Field,
    hash_path: [[u8; 32]; N],
) -> [u8; 32] {
    let index_bits: [u1; N] = index.to_le_bits();
    let mut current = leaf;

    for i in 0..N {
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };

        let mut input: [u8; 64] = [0; 64];
        for j in 0..32 {
            input[j] = hash_left[j];
            input[j + 32] = hash_right[j];
        }

        current = blake3(input);
    }
    current
}

pub fn verify_membership<let N: u32>(
    root: [u8; 32],
    leaf: [u8; 32],
    index: Field,
    hash_path: [[u8; 32]; N],
) {
    let computed_root = compute_merkle_root(leaf, index, hash_path);
    assert(computed_root == root);
}

pub fn verify_multiple_membership<let N: u32, let M: u32>(
    root: [u8; 32],
    leaves: [[u8; 32]; M],
    indices: [Field; M],
    hash_paths: [[[u8; 32]; N]; M],
) {
    for i in 0..M {
        let computed_root = compute_merkle_root(leaves[i], indices[i], hash_paths[i]);
        assert(computed_root == root);
    }
}
#[test]
fn test_four_leaf_merkle_tree() {
    let l1 = blake3("leaf1".as_bytes());
    let l2 = blake3("leaf2".as_bytes());
    let l3 = blake3("leaf3".as_bytes());
    let l4 = blake3("leaf4".as_bytes());

    let mut h12_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        h12_input[i] = l1[i];
        h12_input[i + 32] = l2[i];
    }
    let h12 = blake3(h12_input);

    let mut h34_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        h34_input[i] = l3[i];
        h34_input[i + 32] = l4[i];
    }
    let h34 = blake3(h34_input);

    let mut root_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        root_input[i] = h12[i];
        root_input[i + 32] = h34[i];
    }
    let expected_root = blake3(root_input);

    let hash_path_l1 = [l2, h34];
    let computed_root_l1 = compute_merkle_root(l1, 0 as Field, hash_path_l1);
    assert(computed_root_l1 == expected_root);

    let hash_path_l2 = [l1, h34];
    let computed_root_l2 = compute_merkle_root(l2, 1 as Field, hash_path_l2);
    assert(computed_root_l2 == expected_root);

    let hash_path_l3 = [l4, h12];
    let computed_root_l3 = compute_merkle_root(l3, 2 as Field, hash_path_l3);
    assert(computed_root_l3 == expected_root);

    let hash_path_l4 = [l3, h12];
    let computed_root_l4 = compute_merkle_root(l4, 3 as Field, hash_path_l4);
    assert(computed_root_l4 == expected_root);
}

#[test]
fn test_invalid_membership() {
    let leaf1 = blake3("data1".as_bytes());
    let leaf2 = blake3("data2".as_bytes());
    let fake_leaf = blake3("fake_data".as_bytes());

    let mut root_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        root_input[i] = leaf1[i];
        root_input[i + 32] = leaf2[i];
    }
    let real_root = blake3(root_input);

    let hash_path = [leaf2];

    let computed_root = compute_merkle_root(fake_leaf, 0 as Field, hash_path);
    assert(computed_root != real_root);
}

#[test]
fn test_verify_membership_success_4_leaves() {
    let l1 = blake3("leaf1".as_bytes());
    let l2 = blake3("leaf2".as_bytes());
    let l3 = blake3("leaf3".as_bytes());
    let l4 = blake3("leaf4".as_bytes());

    let mut h12_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        h12_input[i] = l1[i];
        h12_input[i + 32] = l2[i];
    }
    let h12 = blake3(h12_input);

    let mut h34_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        h34_input[i] = l3[i];
        h34_input[i + 32] = l4[i];
    }
    let h34 = blake3(h34_input);

    let mut root_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        root_input[i] = h12[i];
        root_input[i + 32] = h34[i];
    }
    let true_root = blake3(root_input);

    // l1: index=0 (00), path=[l2, h34]
    let path_l1 = [l2, h34];
    verify_membership(true_root, l1, 0, path_l1);

    // l2: index=1 (01), path=[l1, h34]
    let path_l2 = [l1, h34];
    verify_membership(true_root, l2, 1, path_l2);

    // l3: index=2 (10), path=[l4, h12]
    let path_l3 = [l4, h12];
    verify_membership(true_root, l3, 2, path_l3);

    // l4: index=3 (11), path=[l3, h12]
    let path_l4 = [l3, h12];
    verify_membership(true_root, l4, 3, path_l4);
}

#[test]
fn test_verify_parametrized() {
    let l0 = blake3("data0".as_bytes());
    let l1 = blake3("data1".as_bytes());
    let l2 = blake3("data2".as_bytes());
    let l3 = blake3("data3".as_bytes());

    let mut h01_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        h01_input[i] = l0[i];
        h01_input[i + 32] = l1[i];
    }
    let h01 = blake3(h01_input);

    let mut h23_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        h23_input[i] = l2[i];
        h23_input[i + 32] = l3[i];
    }
    let h23 = blake3(h23_input);

    let mut root_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        root_input[i] = h01[i];
        root_input[i + 32] = h23[i];
    }
    let merkle_root = blake3(root_input);

    let leaves = [l0, l1];
    let indices = [0, 1];
    let paths = [
        [l1, h23], // l0: index 0
        [l0, h23],
    ];

    verify_multiple_membership(merkle_root, leaves, indices, paths);
}
