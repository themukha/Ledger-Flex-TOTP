use ledger_device_sdk::ecc::{bip32_derive, CurvesId};
use otp_core::vault::vault_key_from_seed_material;
use zeroize::Zeroizing;

const PATH: [u32; 2] = [0x8000_0000 | 5_198_928, 0x8000_0000];

pub fn vault_key() -> Zeroizing<[u8; 32]> {
    let mut raw = Zeroizing::new([0u8; 64]);
    bip32_derive(CurvesId::Secp256k1, &PATH, raw.as_mut_slice(), None)
        .expect("secp256k1 with a 64-byte buffer is a valid derivation request");
    let mut material = Zeroizing::new([0u8; 32]);
    material.copy_from_slice(&raw[..32]);
    Zeroizing::new(vault_key_from_seed_material(&material))
}
