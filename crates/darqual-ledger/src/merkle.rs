//! A domain-separated blake3 Merkle tree.
//!
//! Leaf nodes:     blake3(0x00 || data)
//! Internal nodes: blake3(0x01 || left || right)
//! Empty tree:     EMPTY_ROOT constant

/// A fixed root returned for an empty leaf set.
pub const EMPTY_ROOT: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(data);
    *h.finalize().as_bytes()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(left.as_slice());
    h.update(right.as_slice());
    *h.finalize().as_bytes()
}

/// Compute the Merkle root of the given leaves.
/// Empty slice → EMPTY_ROOT. Odd layer: duplicate the last node.
pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_ROOT;
    }

    let mut layer: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(hash_node(&layer[i], &layer[i + 1]));
            } else {
                // Odd node — duplicate last
                next.push(hash_node(&layer[i], &layer[i]));
            }
            i += 2;
        }
        layer = next;
    }

    layer[0]
}

/// Inclusion proof: the sibling hashes needed to reconstruct the root.
#[derive(Debug, Clone, PartialEq)]
pub struct MerkleProof {
    pub index: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// Generate an inclusion proof for the leaf at `index`.
pub fn merkle_proof(leaves: &[Vec<u8>], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }

    let mut layer: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
    let mut idx = index;
    let mut siblings = Vec::new();

    while layer.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            // right sibling; if we're the last odd node, sibling is ourselves
            if idx + 1 < layer.len() {
                idx + 1
            } else {
                idx
            }
        } else {
            idx - 1
        };
        siblings.push(layer[sibling_idx]);

        // Build next layer
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(hash_node(&layer[i], &layer[i + 1]));
            } else {
                next.push(hash_node(&layer[i], &layer[i]));
            }
            i += 2;
        }
        idx /= 2;
        layer = next;
    }

    Some(MerkleProof { index, siblings })
}

/// Verify an inclusion proof against a known root.
pub fn verify_proof(root: &[u8; 32], leaf: &[u8], proof: &MerkleProof) -> bool {
    let mut current = hash_leaf(leaf);
    let mut idx = proof.index;

    for sibling in &proof.siblings {
        current = if idx.is_multiple_of(2) {
            hash_node(&current, sibling)
        } else {
            hash_node(sibling, &current)
        };
        idx /= 2;
    }

    &current == root
}
