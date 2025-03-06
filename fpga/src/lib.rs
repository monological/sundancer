mod packet;
use packet::get_packet_offsets;

use solana_packet::{Packet, PACKET_DATA_SIZE};
use {
    solana_signature::Signature,
    solana_pubkey::Pubkey,
    std::{
        mem::size_of,
    },
};

#[link(name = "fpga_ed25519", kind = "static")]
extern "C" {
    fn run_ed25519_verification_on_fpga(
        // All signatures for all packets: 64 bytes each
        signatures_ptr: *const u8,
        // All pubkeys for all packets: 32 bytes each
        pubkeys_ptr: *const u8,
        // All messages for all packets, concatenated
        messages_ptr: *const u8,
        // Offsets into messages_ptr for each packet
        msg_offsets_ptr: *const u32,
        // Length of each packet's message
        msg_sizes_ptr: *const u32,
        // Where each packet's signature(s) begin in the big signatures array
        sig_array_offsets_ptr: *const u32,
        // Number of signatures for each packet
        sig_counts_ptr: *const u32,
        // Total number of packets
        packet_count: usize,
        // Result buffer, 1 byte per packet
        results: *mut u8
    ) -> i32;
}

pub fn ed25519_verify_fpga_batch(
    packets: &mut [Packet],
    reject_non_vote: bool,
) -> Vec<bool> {
    let packet_count = packets.len();

    let mut all_signatures = Vec::new(); // 64 bytes each
    let mut all_pubkeys    = Vec::new(); // 32 bytes each

    let mut messages_buffer = Vec::new();

    // We'll store arrays of message offsets and lengths, one per packet
    let mut msg_offsets = Vec::with_capacity(packet_count);
    let mut msg_sizes   = Vec::with_capacity(packet_count);

    // For distributing the signature results, we must track how many signatures each packet has,
    // plus where they start in all_signatures/all_pubkeys.
    let mut sig_array_offsets = Vec::with_capacity(packet_count);
    let mut sig_counts        = Vec::with_capacity(packet_count);

    // We'll store partial results for each packet:
    //   false => forced fail (e.g. zero sig_len, or partial parse)
    //   true  => we'll see if signatures pass
    let mut packet_ok = vec![true; packet_count];

    // Keep track of how many total signatures across the entire set
    let mut total_signatures = 0;

    for (i, packet) in packets.iter_mut().enumerate() {
        if packet.meta().discard() {
            packet_ok[i] = false;
            // We'll add "bogus" placeholders for the arrays so that
            // we don't skip indexing
            msg_offsets.push(messages_buffer.len() as u32);
            msg_sizes.push(0);
            sig_array_offsets.push(total_signatures as u32);
            sig_counts.push(0);
            continue;
        }

        let offsets = get_packet_offsets(packet, 0, reject_non_vote);

        // If no signatures or other conditions => fail
        if offsets.sig_len == 0 {
            packet_ok[i] = false;
            msg_offsets.push(messages_buffer.len() as u32);
            msg_sizes.push(0);
            sig_array_offsets.push(total_signatures as u32);
            sig_counts.push(0);
            continue;
        }

        if packet.meta().size <= offsets.msg_start as usize {
            packet_ok[i] = false;
            msg_offsets.push(messages_buffer.len() as u32);
            msg_sizes.push(0);
            sig_array_offsets.push(total_signatures as u32);
            sig_counts.push(0);
            continue;
        }

        // Now gather the message
        let msg_start = offsets.msg_start as usize;
        let msg_end = packet.meta().size.min(PACKET_DATA_SIZE);
        let offset_in_message_buffer = messages_buffer.len() as u32;
        let Some(message) = packet.data(msg_start..msg_end) else {
            packet_ok[i] = false;
            msg_offsets.push(messages_buffer.len() as u32);
            msg_sizes.push(0);
            sig_array_offsets.push(total_signatures as u32);
            sig_counts.push(0);
            continue;
        };

        // Append the message once
        messages_buffer.extend_from_slice(message);
        msg_offsets.push(offset_in_message_buffer);
        msg_sizes.push(message.len() as u32);

        // sig_array_offsets => this is where this packet's signatures begin in all_signatures
        // all_signatures is 64 bytes per signature, all_pubkeys is 32 bytes per signature
        sig_array_offsets.push(total_signatures as u32);

        let mut sig_count_for_packet = 0;

        let mut sig_start = offsets.sig_start as usize;
        let mut pubkey_start = offsets.pubkey_start as usize;

        // We'll walk sig_start/pubkey_start repeatedly
        for _ in 0..offsets.sig_len {
            let sig_end = match sig_start.checked_add(size_of::<Signature>()) {
                Some(e) => e,
                None => {
                    packet_ok[i] = false;
                    break;
                }
            };
            let Some(sig_bytes) = packet.data(sig_start..sig_end) else {
                packet_ok[i] = false;
                break;
            };
            all_signatures.extend_from_slice(sig_bytes);

            let pubkey_end = pubkey_start.saturating_add(size_of::<Pubkey>());
            let Some(pub_bytes) = packet.data(pubkey_start..pubkey_end) else {
                packet_ok[i] = false;
                break;
            };
            all_pubkeys.extend_from_slice(pub_bytes);

            sig_start = sig_end;
            pubkey_start = pubkey_end;

            sig_count_for_packet += 1;
        }

        // If we parsed fewer than offsets.sig_len, set fail
        if sig_count_for_packet < offsets.sig_len {
            packet_ok[i] = false;
        }

        sig_counts.push(sig_count_for_packet);
        total_signatures += sig_count_for_packet as usize;
    }

    if total_signatures == 0 {
        return packet_ok;
    }

    let mut result_ptr = vec![0u8; packet_count];

    let rc = unsafe {
        run_ed25519_verification_on_fpga(
            all_signatures.as_ptr(),
            all_pubkeys.as_ptr(),
            messages_buffer.as_ptr(),
            msg_offsets.as_ptr(),
            msg_sizes.as_ptr(),
            sig_array_offsets.as_ptr(),
            sig_counts.as_ptr(),
            packet_count,
            result_ptr.as_mut_ptr(),
        )
    };

    if rc != 0 {
        for ok in packet_ok.iter_mut() {
            *ok = false;
        }
        println!("run_ed25519_verification_on_fpga failed with code {}", rc);
        return packet_ok;
    }

    for (i, ok) in packet_ok.iter_mut().enumerate() {
        if !*ok {
            continue;
        }

        if result_ptr[i] == 0 {
            *ok = false;
        }
    }

    packet_ok
}

pub fn is_available() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use solana_hash::Hash;
    use solana_sdk::{
        signature::{Keypair, Signature},
        system_transaction,
        pubkey::Pubkey,
    };

    #[link(name = "fpga_ed25519", kind = "static")]
    extern "C" {
        fn run_fpga_ed25519_test() -> std::os::raw::c_int;
    }

    #[test]
    fn test_fpga_ed25519_direct() {
        let res = unsafe { run_fpga_ed25519_test() };
        assert_eq!(res, 0, "run_fpga_ed25519_test returned {}", res);
    }

    #[test]
    fn test_ed25519_verify_fpga_batch() {
        let keypair = Keypair::new();
        let recent_blockhash = Hash::new_unique();
        let tx = system_transaction::transfer(
            &keypair,
            &Pubkey::new_unique(),
            42,
            recent_blockhash,
        );

        // Convert the valid transaction into a Packet
        let valid_packet =
            Packet::from_data(None, &tx).expect("Packet::from_data should succeed");

        // Create an *invalid* transaction by overwriting the signature with a default (all-zero)
        // signature
        let mut invalid_tx = tx.clone();
        invalid_tx.signatures[0] = Signature::default();

        let invalid_packet =
            Packet::from_data(None, &invalid_tx).expect("Packet::from_data should succeed");

        // With reject_non_vote = false, we expect [true, false]
        let results = ed25519_verify_fpga_batch(&mut [valid_packet.clone(), invalid_packet.clone()], false);
        assert_eq!(
            results,
            vec![true, false],
            "Expected valid to pass, invalid to fail"
        );

        // With reject_non_vote = true, these are system (not vote) tx => both should fail
        let results_reject = ed25519_verify_fpga_batch(&mut [valid_packet, invalid_packet], true);
        assert_eq!(
            results_reject,
            vec![false, false],
            "Expected both packets to fail when non-votes are rejected"
        );
    }
}

