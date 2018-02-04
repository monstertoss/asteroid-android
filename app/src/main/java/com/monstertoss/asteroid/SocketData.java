package com.monstertoss.asteroid;

import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Random;

class SocketData {

    private static String TAG = "SocketData";

    static int ID_LENGTH = 32;

    // Initialize socket data
    SocketData(Socket socket) {
        this.socket = socket;
        this.state = SocketState.UNKNOWN;

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

    Thread thread;

    // The client's public key and fingerprint, if state != UNKNOWN.
    RSAPublicKey publicKey;
    String fingerprint;

    // Challenge sent to the client, if the socket is beyond the CHALLENGE_SENT step
    String challenge;

    // Higher level input and output streams and buffers (after tls encryption). This is used during IO processing
    BufferedInputStream inputStream;
    BufferedOutputStream outputStream;

    ArrayList<Packet> inputBuffer;
    ArrayList<Packet> outputBuffer;

    // Queue a packet to be sent
    void send(MessageOpcode opCode, JSONObject message) {
        outputBuffer.add(new Packet(opCode, message));
        String payload = message.toString();

        Log.d(TAG, "Sending message with opcode: " + opCode.ordinal() + " and content: " + (payload.length() > 100 ? payload.substring(0, 100) + "..." : payload));
    }

    void close() {
        thread.interrupt();
        try {
            if (!socket.isClosed())
                socket.close();
        } catch(IOException e) {}
    }
}
