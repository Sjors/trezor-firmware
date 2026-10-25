/**
 * Copyright (c) SatoshiLabs
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdbool.h>
#include <string.h>

#include "memzero.h"
#include "sha2.h"
#include "zkp_context.h"

#include "vendor/secp256k1-zkp/include/secp256k1.h"
#include "vendor/secp256k1-zkp/include/secp256k1_extrakeys.h"
#include "vendor/secp256k1-zkp/include/secp256k1_schnorrsig.h"

#include "zkp_bip340.h"

// Initial hash value H for SHA-256 TapTweak:
const uint32_t sha256_initial_taptweak_state[8] = {
    0xd129a2f3UL, 0x701c655dUL, 0x6583b6c3UL, 0xb9419727UL,
    0x95f4e232UL, 0x94fd54f4UL, 0xa2ae8d85UL, 0x47ca590bUL,
};

// BIP340 Schnorr public key derivation
// private_key_bytes has 32 bytes
// public_key_bytes has 32 bytes
// returns 0 on success
int zkp_bip340_get_public_key(const uint8_t *private_key_bytes,
                              uint8_t *public_key_bytes) {
  int result = 0;

  secp256k1_context *context_writable = NULL;
  if (result == 0) {
    context_writable = zkp_context_acquire_writable();
    if (context_writable == NULL) {
      result = -1;
    }
  }
  if (result == 0) {
    if (secp256k1_context_writable_randomize(context_writable) != 0) {
      result = -1;
    }
  }

  secp256k1_pubkey public_key = {0};
  if (result == 0) {
    if (secp256k1_ec_pubkey_create(context_writable, &public_key,
                                   private_key_bytes) != 1) {
      result = -1;
    }
  }

  if (context_writable) {
    zkp_context_release_writable();
    context_writable = NULL;
  }

  secp256k1_xonly_pubkey xonly_pubkey = {0};
  const secp256k1_context *context_read_only = zkp_context_get_read_only();

  if (result == 0) {
    if (secp256k1_xonly_pubkey_from_pubkey(context_read_only, &xonly_pubkey,
                                           NULL, &public_key) != 1) {
      result = -1;
    }
  }

  memzero(&public_key, sizeof(public_key));

  if (result == 0) {
    if (secp256k1_xonly_pubkey_serialize(context_read_only, public_key_bytes,
                                         &xonly_pubkey) != 1) {
      result = -1;
    }
  }

  memzero(&xonly_pubkey, sizeof(xonly_pubkey));

  return result;
}

// BIP340 Schnorr signature signing
// private_key_bytes has 32 bytes
// digest has 32 bytes
// signature_bytes has 64 bytes
// auxiliary_data has 32 bytes or is NULL (32 zero bytes are used)
// returns 0 on success
int zkp_bip340_sign_digest(const uint8_t *private_key_bytes,
                           const uint8_t *digest, uint8_t *signature_bytes,
                           uint8_t *auxiliary_data) {
  int result = 0;

  secp256k1_context *context_writable = NULL;
  if (result == 0) {
    context_writable = zkp_context_acquire_writable();
    if (context_writable == NULL) {
      result = -1;
    }
  }
  if (result == 0) {
    if (secp256k1_context_writable_randomize(context_writable) != 0) {
      result = -1;
    }
  }

  secp256k1_keypair keypair = {0};
  if (result == 0) {
    if (secp256k1_keypair_create(context_writable, &keypair,
                                 private_key_bytes) != 1) {
      result = -1;
    }
  }

  if (result == 0) {
    if (secp256k1_context_writable_randomize(context_writable) != 0) {
      result = -1;
    }
  }

  if (result == 0) {
    if (secp256k1_schnorrsig_sign32(context_writable, signature_bytes, digest,
                                    &keypair, auxiliary_data) != 1) {
      result = -1;
    }
  }

  if (context_writable) {
    zkp_context_release_writable();
    context_writable = NULL;
  }

  memzero(&keypair, sizeof(keypair));

  return result;
}

// BIP340 Schnorr signature verification
// public_key_bytes has 32 bytes
// signature_bytes has 64 bytes
// digest has 32 bytes
// returns 0 if verification succeeded
int zkp_bip340_verify_digest(const uint8_t *public_key_bytes,
                             const uint8_t *signature_bytes,
                             const uint8_t *digest) {
  int result = 0;

  secp256k1_xonly_pubkey xonly_pubkey = {0};
  const secp256k1_context *context_read_only = zkp_context_get_read_only();

  if (result == 0) {
    if (secp256k1_xonly_pubkey_parse(context_read_only, &xonly_pubkey,
                                     public_key_bytes) != 1) {
      result = 1;
    }
  }

  if (result == 0) {
    if (secp256k1_schnorrsig_verify(context_read_only, signature_bytes, digest,
                                    32, &xonly_pubkey) != 1) {
      result = 5;
    }
  }

  memzero(&xonly_pubkey, sizeof(xonly_pubkey));

  return result;
}

// BIP340 Schnorr public key verification
// public_key_bytes has 32 bytes
// returns 0 if verification succeeded
int zkp_bip340_verify_publickey(const uint8_t *public_key_bytes) {
  int result = 0;

  secp256k1_xonly_pubkey xonly_pubkey = {0};
  const secp256k1_context *context_read_only = zkp_context_get_read_only();

  if (result == 0) {
    if (secp256k1_xonly_pubkey_parse(context_read_only, &xonly_pubkey,
                                     public_key_bytes) != 1) {
      result = 1;
    }
  }

  memzero(&xonly_pubkey, sizeof(xonly_pubkey));

  return result;
}

// BIP340 Schnorr public key tweak
// internal_public_key has 32 bytes
// root_hash has 32 bytes or is empty (NULL)
// output_public_key has 32 bytes
// returns 0 on success
int zkp_bip340_tweak_public_key(const uint8_t *internal_public_key,
                                const uint8_t *root_hash,
                                uint8_t *output_public_key) {
  int result = 0;

  uint8_t tweak[SHA256_DIGEST_LENGTH] = {0};
  if (result == 0) {
    SHA256_CTX ctx = {0};
    sha256_Init_ex(&ctx, sha256_initial_taptweak_state, 512);
    sha256_Update(&ctx, internal_public_key, 32);
    if (root_hash != NULL) {
      sha256_Update(&ctx, root_hash, 32);
    }
    sha256_Final(&ctx, tweak);
  }

  const secp256k1_context *context_read_only = zkp_context_get_read_only();

  secp256k1_xonly_pubkey internal_pubkey = {0};
  if (result == 0) {
    if (secp256k1_xonly_pubkey_parse(context_read_only, &internal_pubkey,
                                     internal_public_key) != 1) {
      result = -1;
    }
  }

  secp256k1_pubkey output_pubkey = {0};
  if (result == 0) {
    if (secp256k1_xonly_pubkey_tweak_add(context_read_only, &output_pubkey,
                                         &internal_pubkey, tweak) != 1) {
      result = -1;
    }
  }

  memzero(tweak, sizeof(tweak));
  memzero(&internal_pubkey, sizeof(internal_pubkey));

  secp256k1_xonly_pubkey xonly_output_pubkey = {0};
  if (result == 0) {
    if (secp256k1_xonly_pubkey_from_pubkey(context_read_only,
                                           &xonly_output_pubkey, NULL,
                                           &output_pubkey) != 1) {
      result = -1;
    }
  }

  memzero(&output_pubkey, sizeof(output_pubkey));

  if (result == 0) {
    if (secp256k1_xonly_pubkey_serialize(context_read_only, output_public_key,
                                         &xonly_output_pubkey) != 1) {
      result = -1;
    }
  }

  memzero(&xonly_output_pubkey, sizeof(xonly_output_pubkey));

  return result;
}

// BIP340 Schnorr private key tweak
// internal_private_key has 32 bytes
// root_hash has 32 bytes or is empty (NULL)
// output_private_key has 32 bytes
// returns 0 on success
int zkp_bip340_tweak_private_key(const uint8_t *internal_private_key,
                                 const uint8_t *root_hash,
                                 uint8_t *output_private_key) {
  int result = 0;

  secp256k1_context *context_writable = NULL;
  if (result == 0) {
    context_writable = zkp_context_acquire_writable();
    if (context_writable == NULL) {
      result = -1;
    }
  }
  if (result == 0) {
    if (secp256k1_context_writable_randomize(context_writable) != 0) {
      result = -1;
    }
  }

  secp256k1_keypair keypair = {0};
  if (result == 0) {
    if (secp256k1_keypair_create(context_writable, &keypair,
                                 internal_private_key) != 1) {
      result = -1;
    }
  }

  if (context_writable) {
    zkp_context_release_writable();
    context_writable = NULL;
  }

  const secp256k1_context *context_read_only = zkp_context_get_read_only();

  secp256k1_xonly_pubkey internal_xonly_pubkey = {0};
  if (result == 0) {
    if (secp256k1_keypair_xonly_pub(context_read_only, &internal_xonly_pubkey,
                                    NULL, &keypair) != 1) {
      result = -1;
    }
  }

  uint8_t internal_public_key[32] = {0};
  if (result == 0) {
    if (secp256k1_xonly_pubkey_serialize(context_read_only, internal_public_key,
                                         &internal_xonly_pubkey) != 1) {
      result = -1;
    }
  }

  memzero(&internal_xonly_pubkey, sizeof(internal_xonly_pubkey));

  uint8_t tweak[SHA256_DIGEST_LENGTH] = {0};
  if (result == 0) {
    SHA256_CTX ctx = {0};
    sha256_Init_ex(&ctx, sha256_initial_taptweak_state, 512);
    sha256_Update(&ctx, internal_public_key, 32);
    if (root_hash != NULL) {
      sha256_Update(&ctx, root_hash, 32);
    }
    sha256_Final(&ctx, tweak);
  }

  memzero(&internal_public_key, sizeof(internal_public_key));

  if (result == 0) {
    if (secp256k1_keypair_xonly_tweak_add(context_read_only, &keypair, tweak) !=
        1) {
      result = -1;
    }
  }

  memzero(tweak, sizeof(tweak));

  if (result == 0) {
    if (secp256k1_keypair_sec(context_read_only, output_private_key,
                              &keypair) != 1) {
      result = -1;
    }
  }

  memzero(&keypair, sizeof(keypair));

  return result;
}

// These domains are provisional pending assignment of a BIP number.
static void anti_exfil_hash(const char *tag, const uint8_t *data, size_t size,
                            uint8_t out[32]) {
  uint8_t tag_hash[32] = {0};
  sha256_Raw((const uint8_t *)tag, strlen(tag), tag_hash);
  SHA256_CTX hash = {0};
  sha256_Init(&hash);
  sha256_Update(&hash, tag_hash, 32);
  sha256_Update(&hash, tag_hash, 32);
  sha256_Update(&hash, data, size);
  sha256_Final(&hash, out);
  memzero(tag_hash, sizeof(tag_hash));
}

// A 256-bit hash is less than twice the group order, so one conditional
// subtraction reduces it. Avoid branching on the secret nonce hash.
static void anti_exfil_reduce(uint8_t scalar[32]) {
  static const uint8_t order[32] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
      0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
  uint8_t reduced[32] = {0};
  uint16_t borrow = 0;
  for (int i = 31; i >= 0; --i) {
    uint16_t difference = (uint16_t)scalar[i] - order[i] - borrow;
    reduced[i] = difference & 0xff;
    borrow = difference >> 15;
  }
  uint8_t mask = (uint8_t)(borrow - 1);
  for (size_t i = 0; i < 32; ++i) {
    scalar[i] = (reduced[i] & mask) | (scalar[i] & (uint8_t)~mask);
  }
  memzero(reduced, sizeof(reduced));
}

static int anti_exfil_nonce_function(unsigned char *nonce32,
                                     const unsigned char *msg, size_t msglen,
                                     const unsigned char *key32,
                                     const unsigned char *xonly_pk32,
                                     const unsigned char *algo, size_t algolen,
                                     void *data) {
  (void)msg;
  (void)key32;
  (void)xonly_pk32;
  (void)algo;
  (void)algolen;
  if (msglen != 32) return 0;
  memcpy(nonce32, data, 32);
  return 1;
}

static int anti_exfil(const uint8_t *private_key, const uint8_t *digest,
                      const uint8_t *commitment, const uint8_t *signer_nonce,
                      const uint8_t *entropy, uint8_t *out) {
  int result = -1;
  secp256k1_context *ctx = zkp_context_acquire_writable();
  if (ctx == NULL) return -1;
  secp256k1_keypair keypair = {0};
  secp256k1_xonly_pubkey pubkey = {0};
  secp256k1_pubkey nonce_point = {0};
  uint8_t normalized[32] = {0}, masked[96] = {0}, aux[32] = {0};
  uint8_t nonce[32] = {0}, encoded_nonce[33] = {0}, opening[32] = {0};
  int parity = 0;
  size_t encoded_size = sizeof(encoded_nonce);

  if (secp256k1_context_writable_randomize(ctx) != 0 ||
      secp256k1_keypair_create(ctx, &keypair, private_key) != 1 ||
      secp256k1_keypair_xonly_pub(ctx, &pubkey, &parity, &keypair) != 1 ||
      secp256k1_xonly_pubkey_serialize(ctx, masked + 32, &pubkey) != 1) {
    goto cleanup;
  }
  memcpy(normalized, private_key, 32);
  if (parity && secp256k1_ec_seckey_negate(ctx, normalized) != 1) goto cleanup;
  anti_exfil_hash("BIP0340/aux", commitment, 32, aux);
  for (size_t i = 0; i < 32; ++i) masked[i] = normalized[i] ^ aux[i];
  memcpy(masked + 64, digest, 32);
  // Do not use BIP0340/nonce: ordinary signing must never reuse k0.
  anti_exfil_hash("BIP-EXFIL/nonce", masked, sizeof(masked), nonce);
  anti_exfil_reduce(nonce);
  if (secp256k1_ec_pubkey_create(ctx, &nonce_point, nonce) != 1 ||
      secp256k1_ec_pubkey_serialize(ctx, encoded_nonce, &encoded_size,
                                    &nonce_point,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    goto cleanup;
  }
  if (entropy == NULL) {
    memcpy(out, encoded_nonce, 33);
    result = 0;
    goto cleanup;
  }
  anti_exfil_hash("BIP-EXFIL/host", entropy, 32, opening);
  if (signer_nonce == NULL || memcmp(opening, commitment, 32) != 0 ||
      memcmp(encoded_nonce, signer_nonce, 33) != 0 ||
      secp256k1_ec_seckey_verify(ctx, entropy) != 1 ||
      secp256k1_ec_seckey_tweak_add(ctx, nonce, entropy) != 1) {
    goto cleanup;
  }
  secp256k1_schnorrsig_extraparams params =
      SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
  params.noncefp = anti_exfil_nonce_function;
  params.ndata = nonce;
  if (secp256k1_schnorrsig_sign_custom(ctx, out, digest, 32, &keypair,
                                       &params) != 1 ||
      secp256k1_schnorrsig_verify(ctx, out, digest, 32, &pubkey) != 1) {
    goto cleanup;
  }
  result = 0;
cleanup:
  memzero(&keypair, sizeof(keypair));
  memzero(normalized, sizeof(normalized));
  memzero(masked, sizeof(masked));
  memzero(aux, sizeof(aux));
  memzero(nonce, sizeof(nonce));
  memzero(encoded_nonce, sizeof(encoded_nonce));
  memzero(opening, sizeof(opening));
  zkp_context_release_writable();
  if (result != 0) memzero(out, entropy == NULL ? 33 : 64);
  return result;
}

int zkp_bip340_anti_exfil_commit(const uint8_t *private_key,
                                 const uint8_t *digest,
                                 const uint8_t *commitment,
                                 uint8_t *signer_nonce) {
  return anti_exfil(private_key, digest, commitment, NULL, NULL, signer_nonce);
}

int zkp_bip340_anti_exfil_sign(const uint8_t *private_key,
                               const uint8_t *digest, const uint8_t *commitment,
                               const uint8_t *signer_nonce,
                               const uint8_t *entropy, uint8_t *signature) {
  return anti_exfil(private_key, digest, commitment, signer_nonce, entropy,
                    signature);
}
