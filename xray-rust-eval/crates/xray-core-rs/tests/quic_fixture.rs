use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
    0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

pub fn build_test_quic_initial_packet(host: &str) -> Vec<u8> {
    let handshake = tls_client_hello_handshake(host);
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let scid = [0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let packet_number = 0u64;
    let packet_number_len = 1usize;

    let mut plaintext = vec![0x06];
    encode_varint(0, &mut plaintext);
    encode_varint(handshake.len() as u64, &mut plaintext);
    plaintext.extend_from_slice(&handshake);

    let secret = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dcid);
    let mut initial_secret = [0; 32];
    secret
        .expand(&tls_label(32, b"client in"), &mut initial_secret)
        .unwrap();
    let hk = Hkdf::<Sha256>::from_prk(&initial_secret).unwrap();
    let mut key = [0; 16];
    hk.expand(&tls_label(16, b"quic key"), &mut key).unwrap();
    let mut iv = [0; 12];
    hk.expand(&tls_label(12, b"quic iv"), &mut iv).unwrap();
    let mut hp = [0; 16];
    hk.expand(&tls_label(16, b"quic hp"), &mut hp).unwrap();

    let mut header = Vec::new();
    header.push(0xc0);
    header.extend_from_slice(&1u32.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(&dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(&scid);
    encode_varint(0, &mut header);
    encode_varint(packet_number_len as u64 + plaintext.len() as u64 + 16, &mut header);
    let packet_number_offset = header.len();
    header.push(packet_number as u8);

    let mut nonce = iv;
    for (index, byte) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .unwrap();
    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    let hp_cipher = Aes128::new_from_slice(&hp).unwrap();
    let sample_offset = packet_number_offset + 4;
    let mut sample = aes::cipher::Block::<Aes128>::clone_from_slice(
        &packet[sample_offset..sample_offset + 16],
    );
    hp_cipher.encrypt_block(&mut sample);
    packet[0] ^= sample[0] & 0x0f;
    packet[packet_number_offset] ^= sample[1];
    packet
}

fn tls_client_hello_handshake(host: &str) -> Vec<u8> {
    let mut sni = vec![0];
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    let mut sni_extension = Vec::new();
    sni_extension.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_extension.extend_from_slice(&sni);
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_extension);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&[
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&body);
    handshake
}

fn tls_label(length: u16, label: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&length.to_be_bytes());
    output.push((6 + label.len()) as u8);
    output.extend_from_slice(b"tls13 ");
    output.extend_from_slice(label);
    output.push(0);
    output
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    }
}
