#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

/*
 * run_ed25519_verification_on_fpga
 *
 * Verifies one or more packets worth of Ed25519 signatures. Each packet
 * can have one or more signatures. We assume the following layout:
 *
 *  - 'signatures_ptr' is a contiguous array of all Ed25519 signatures (64 bytes each).
 *  - 'pubkeys_ptr'    is a contiguous array of corresponding Ed25519 public keys (32 bytes each).
 *  - 'messages_ptr'   is a contiguous array of all message bytes for all packets.
 *
 *  - 'msg_offsets_ptr[i]' gives the offset (in bytes) in 'messages_ptr' for packet i's message.
 *  - 'msg_sizes_ptr[i]'   gives the size (in bytes) of packet i's message.
 *
 *  - 'sig_array_offsets_ptr[i]' gives the index (NOT byte offset) into 'signatures_ptr'
 *        and 'pubkeys_ptr' for the first signature/public-key pair for packet i.
 *        For example, if sig_array_offsets_ptr[i] = 3, that means the first signature
 *        for packet i starts at signatures_ptr + (3 * 64). The corresponding public key
 *        would be at pubkeys_ptr + (3 * 32).
 *
 *  - 'sig_counts_ptr[i]' gives the number of signatures in packet i.
 *
 *  - 'packet_count' is how many packets to verify in total.
 *
 *  - 'results' is a buffer of 'packet_count' bytes. results[i] = 1 if ALL
 *        signatures for packet i verify successfully, else 0
 *
 */
int run_ed25519_verification_on_fpga(
    const uint8_t* signatures_ptr,
    const uint8_t* pubkeys_ptr,
    const uint8_t* messages_ptr,
    const uint32_t* msg_offsets_ptr,
    const uint32_t* msg_sizes_ptr,
    const uint32_t* sig_array_offsets_ptr,
    const uint32_t* sig_counts_ptr,
    size_t packet_count,
    uint8_t *results
) {

    if(results == NULL) {
        return -1;
    }

    for (size_t i = 0; i < packet_count; i++) {
        // Get the message offset and size for this packet
        const uint8_t* msg_ptr = messages_ptr + msg_offsets_ptr[i];
        size_t msg_len = msg_sizes_ptr[i];

        // How many signatures are we verifying for this packet?
        size_t sig_count = sig_counts_ptr[i];
        // Where do these signatures start in the global signature array?
        size_t sig_start_index = sig_array_offsets_ptr[i];

        // We will mark this packet as "valid" if ALL its signatures pass.
        int all_signatures_valid = 1;

        // Verify each signature in this packet
        for (size_t j = 0; j < sig_count; j++) {
            // The j-th signature for this packet is at index (sig_start_index + j)
            size_t idx = sig_start_index + j;

            // Each Ed25519 signature is 64 bytes
            const uint8_t* sig_ptr = signatures_ptr + (idx * 64);
            // Each Ed25519 public key is 32 bytes
            const uint8_t* pk_ptr  = pubkeys_ptr    + (idx * 32);

            if (crypto_sign_verify_detached(sig_ptr, msg_ptr, (unsigned long long)msg_len, pk_ptr) != 0) {
                all_signatures_valid = 0;
                break;
            }
        }

        results[i] = (uint8_t) (all_signatures_valid ? 1 : 0);
    }

    return 0;
}

static void sign_and_store(
    int index,
    const uint8_t* msg,
    size_t msg_len,
    const unsigned char* pk,
    const unsigned char* sk,
    uint8_t* signatures_array,
    uint8_t* pubkeys_array
) {
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, msg, (unsigned long long)msg_len, sk);
    memcpy(signatures_array + (index * 64), sig, 64);
    memcpy(pubkeys_array    + (index * 32), pk,  32);
}

int run_fpga_ed25519_test(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed!\n");
        return 1;
    }

    const char* msg0 = "Hello, world!";
    const char* msg1 = "Goodbye, world!";
    uint8_t messages[128];
    size_t msg0_len = 13;
    size_t msg1_len = 15;

    memcpy(messages, msg0, msg0_len);
    memcpy(messages + msg0_len, msg1, msg1_len);

    uint32_t msg_offsets[2];
    msg_offsets[0] = 0;
    msg_offsets[1] = (uint32_t)msg0_len;

    uint32_t msg_sizes[2];
    msg_sizes[0] = (uint32_t)msg0_len;
    msg_sizes[1] = (uint32_t)msg1_len;

    uint8_t signatures[4 * 64];
    uint8_t pubkeys[4 * 32];
    unsigned char pks[4][crypto_sign_PUBLICKEYBYTES];
    unsigned char sks[4][crypto_sign_SECRETKEYBYTES];

    for (int i = 0; i < 4; i++) {
        crypto_sign_keypair(pks[i], sks[i]);
    }

    uint32_t sig_array_offsets[2];
    uint32_t sig_counts[2];
    sig_array_offsets[0] = 0;
    sig_counts[0]        = 2;
    sig_array_offsets[1] = 2;
    sig_counts[1]        = 2;


    sign_and_store(0, messages + msg_offsets[0], msg_sizes[0],
                   pks[0], sks[0], signatures, pubkeys);
    sign_and_store(1, messages + msg_offsets[0], msg_sizes[0],
                   pks[1], sks[1], signatures, pubkeys);
    sign_and_store(2, messages + msg_offsets[1], msg_sizes[1],
                   pks[2], sks[2], signatures, pubkeys);
    sign_and_store(3, messages + msg_offsets[1], msg_sizes[1],
                   pks[3], sks[3], signatures, pubkeys);

    uint8_t* verify_results = calloc(2, sizeof(uint8_t));

    int ret = run_ed25519_verification_on_fpga(
        signatures,
        pubkeys,
        messages,
        msg_offsets,
        msg_sizes,
        sig_array_offsets,
        sig_counts,
        2,
        verify_results
    );

    if (ret != 0) {
        fprintf(stderr, "Unexpected error from FPGA verification\n");
        return 1;
    }

    if (verify_results[0] != 1 || verify_results[1] != 1) {
        fprintf(stderr, "Initial verify failed\n");
        return 1;
    }

    memset(verify_results, 0, 2);

    signatures[2 * 64] ^= 0xFF;
    ret = run_ed25519_verification_on_fpga(
        signatures,
        pubkeys,
        messages,
        msg_offsets,
        msg_sizes,
        sig_array_offsets,
        sig_counts,
        2,
        verify_results
    );

    if ( ret != 0) {
        fprintf(stderr, "Unexpected error from FPGA verification\n");
        return 1;
    }

    if (verify_results[0] != 1 || verify_results[1] != 0) {
        fprintf(stderr, "Corruption test failed\n");
        return 1;
    }

    free(verify_results);

    return 0;
}

