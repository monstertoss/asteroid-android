package com.monstertoss.asteroid;

enum MessageOpcode {
    // First, the client sends its public key
    C2S_HANDSHAKE_PUBLIC_KEY,
    // The server responds if the key is known or unknown, in the latter case the client shows its fingerprint for confirmation. KNOWN is also sent after confirming the key for the client to hide it again.
    S2C_HANDSHAKE_PUBLIC_KEY_UNKNOWN,
    S2C_HANDSHAKE_PUBLIC_KEY_KNOWN,
    // Server sends challenge to client
    S2C_HANDSHAKE_CHALLENGE,
    // RESERVED. Client challenging the server
    C2S_HANDSHAKE_CHALLENGE,
    // Client response to server challenge
    C2S_HANDSHAKE_RESPONSE,
    // RESERVED. Server response to client challenge
    S2C_HANDSHAKE_RESPONSE,
    // Server OK to client response
    S2C_HANDSHAKE_OK,
    // RESERVED. Client OK to server response
    C2S_HANDSHAKE_OK;

    // Convert byte to opcode
    static MessageOpcode from(byte value) {
        try {
            return MessageOpcode.values()[value];
        } catch(ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }
}
