package com.monstertoss.asteroid;

import android.util.Base64;
import android.util.Log;

import com.monstertoss.zstd_android.Zstd;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Packet {
    MessageOpcode opCode;
    JSONObject payload;

    byte rawOpcode;
    String rawPayload;

    static final int MAX_PACKAGE_SIZE = 8192;

    public Packet(MessageOpcode opCode, JSONObject payload) {
        this.opCode = opCode;
        rawOpcode = (byte)opCode.ordinal();
        this.payload = payload;
        rawPayload = payload.toString();
    }

    public Packet(byte[] bytes) {
        // Packets are built like that
        // 1 byte opcode, is any of the MessageOpcode enum
        // 4 byte integer: original size of compressed body
        // Base64 encoded compressed JSON body
        // 0xFF as delimiter (not included here)

        // Parse opcode
        rawOpcode = bytes[0];
        opCode = MessageOpcode.from(rawOpcode);

        int decompressedSize = ByteBuffer.wrap(bytes, 1, 4).getInt();

        byte[] message = Base64.decode(bytes, 5, bytes.length - 5, Base64.NO_WRAP);

        byte[] decompressed = new byte[decompressedSize];
        Zstd.decompress(decompressed, message);

        // parse Json
        rawPayload = new String(decompressed);
        try {
            payload = new JSONObject(rawPayload);
        } catch(JSONException e) {
            payload = null;
        }
    }

    public boolean isValid() {
        return opCode != null && payload != null;
    }

    public int getSize() {
        return 1 /* opcode */ + ((int)Math.ceil(rawPayload.length()/3)*4) + 1 /* delimiter */;
    }

    public MessageOpcode getOpCode() {
        return opCode;
    }

    public byte getRawOpcode() {
        return rawOpcode;
    }

    public JSONObject getPayload() {
        return payload;
    }

    public String getRawPayload() {
        return rawPayload;
    }

    public byte[] encodePayload() {
        byte[] compressed = Zstd.compress(rawPayload.getBytes(), 1);
        return Base64.encode(compressed, Base64.NO_WRAP);
    }

    @Override
    public String toString() {
        return "[Packet: " + (isValid() ? "VALID" : "INVALID") + " " + rawOpcode + " " + rawPayload + "]";
    }
}
