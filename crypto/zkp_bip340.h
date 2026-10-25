#ifndef __ZKP_BIP340_H__
#define __ZKP_BIP340_H__

#include <stdint.h>

int zkp_bip340_get_public_key(const uint8_t *private_key_bytes,
                              uint8_t *public_key_bytes);
int zkp_bip340_sign_digest(const uint8_t *private_key_bytes,
                           const uint8_t *digest, uint8_t *signature_bytes,
                           uint8_t *auxiliary_data);
int zkp_bip340_verify_digest(const uint8_t *public_key_bytes,
                             const uint8_t *signature_bytes,
                             const uint8_t *digest);
int zkp_bip340_verify_publickey(const uint8_t *public_key_bytes);
int zkp_bip340_tweak_public_key(const uint8_t *internal_public_key,
                                const uint8_t *root_hash,
                                uint8_t *output_public_key);
int zkp_bip340_tweak_private_key(const uint8_t *internal_private_key,
                                 const uint8_t *root_hash,
                                 uint8_t *output_private_key);

// Draft BIP-EXFIL, using the actual Taproot-tweaked secret key. Returns 0 on
// success. All inputs are fixed-size; commitment and entropy are 32 bytes,
// signer_nonce is a full compressed 33-byte point (including its parity).
int zkp_bip340_anti_exfil_commit(const uint8_t *private_key,
                                 const uint8_t *digest,
                                 const uint8_t *commitment,
                                 uint8_t *signer_nonce);
int zkp_bip340_anti_exfil_sign(const uint8_t *private_key,
                               const uint8_t *digest, const uint8_t *commitment,
                               const uint8_t *signer_nonce,
                               const uint8_t *entropy, uint8_t *signature);

#endif
