package com.monstertoss.asteroid;

import android.util.Base64;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Random;

class SocketData {

    static int ID_LENGTH = 32;

    // Initialize socket data
    SocketData(Socket socket) {
        this.socket = socket;
        this.state = SocketState.UNKNOWN;
        this.shouldBeRunning = true;

        Random randomService = new Random();
        StringBuilder sb = new StringBuilder();
        while (sb.length() < ID_LENGTH) {
            sb.append(Integer.toHexString(randomService.nextInt()));
        }
        sb.setLength(ID_LENGTH);
        this.id = sb.toString();

        this.inputBuffer = new ArrayList<>();
        this.outputBuffer = new ArrayList<>();
    }

    // Unique ID of the socket (should be unique :P)
    String id;
    // The low level unencrypted socket
    Socket socket;
    // The socket's state. For normal usage, this should always be checked to be AUTHORIZED
    SocketState state;
    // This starts with true and should be set to false on any error or intended socket close. This triggers the socket to be closed and all cleanup to happen
    boolean shouldBeRunning;

    // The client's public key and fingerprint, if state != UNKNOWN.
    RSAPublicKey publicKey;
    String fingerprint;

    // Challenge sent to the client, if the socket is beyond the CHALLENGE_SENT step
    String challenge;

    // Higher level input and output streams and buffers (after tls encryption). This is used during IO processing
    BufferedInputStream inputStream;
    BufferedOutputStream outputStream;

    ArrayList<ArrayList<Byte>> inputBuffer;
    ArrayList<ArrayList<Byte>> outputBuffer;

    // Queue a packet to be sent
    void send(MessageOpcode opCode, JSONObject message) {
        ArrayList<Byte> msg = new ArrayList<>();

        // Convert JSON to string and encode with Base64
        String jsonString = message.toString();
        byte[] bytes = new byte[0];
        try {
            bytes = Base64.encode(jsonString.getBytes("UTF-8"), Base64.NO_WRAP);
        } catch(UnsupportedEncodingException e) {}

        // First the opcode, then the message, then a linebreak
        msg.add((byte)opCode.ordinal());
        for(byte b : bytes) {
            msg.add(b);
        }
        msg.add((byte)'\n');

        outputBuffer.add(msg);
    }
}
