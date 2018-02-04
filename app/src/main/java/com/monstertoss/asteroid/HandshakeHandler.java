package com.monstertoss.asteroid;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.SecureRandom;

import static com.monstertoss.asteroid.MessageOpcode.*;
import static com.monstertoss.asteroid.SocketState.*;

class HandshakeHandler {
    private static final String TAG = "HandshakeHandler";

    static void HandlePublicKey(final ServerService context, Packet packet, final SocketData data) {
        // Allow only if the client is yet unknown (allow this operation only once)
        if (data.state != UNKNOWN) {
            Log.d(TAG, "[" + data.id + "] Closing: Got C2S_HANDSHAKE_PUBLIC_KEY but state isn't UNKNOWN");
            data.close();
            return;
        }

        // Decode the public key
        try {
            final String keyString = packet.getPayload().getString("key");
            byte[] key = Base64.decode(keyString, Base64.NO_WRAP);
            data.publicKey = SecurityHelper.byteArrayToPublicKey(key);

            // Close the socket if an invalid public key was sent
            if (data.publicKey == null) {
                Log.d(TAG, "[" + data.id + "] Closing: Got invalid public key");
                data.close();
                return;
            }
            // Compute the key's fingerprint.
            data.fingerprint = SecurityHelper.calculateFingerprint(data.publicKey.getEncoded());

            Log.d(TAG, "[" + data.id + "] Received public key: " + data.fingerprint);

            // Query our database
            if (context.keyDB.DoesFingerprintExist(data.fingerprint)) {
                // Client is known, proceed to sending a challenge
                data.state = KNOWN_PUBLIC_KEY;
                data.send(S2C_HANDSHAKE_PUBLIC_KEY_KNOWN, new JSONObject());

                sendChallenge(context, data);
            } else {
                // Notify UI to show a popup to confirm this client
                data.state = UNKNOWN_PUBLIC_KEY;
                data.send(S2C_HANDSHAKE_PUBLIC_KEY_UNKNOWN, new JSONObject());

                // Broadcast receiver after either OK or Cancel is clicked in the UI
                context.broadcasts.addBroadcastListener(new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context c, Intent intent) {
                        context.broadcasts.removeBroadcastListener("ServerService.confirmKeyDialogResponse:" + data.fingerprint);
                        boolean confirmed = intent.getBooleanExtra("confirmed", false);

                        Log.v(TAG, "[" + data.id + "] " + (confirmed ? "Rejected" : "Confirmed") + " key: " + data.fingerprint);

                        // If the key was confirmed, store that in our database and proceed with sending a challenge, otherwise close the socket.
                        if (confirmed) {
                            context.keyDB.PutKey(keyString, data.fingerprint);
                            data.state = KNOWN_PUBLIC_KEY;
                            data.send(S2C_HANDSHAKE_PUBLIC_KEY_KNOWN, new JSONObject());

                            sendChallenge(context, data);
                        } else {
                            data.close();
                            Log.d(TAG, "[" + data.id + "] Closing: Public key rejected by user");
                        }
                    }
                }, "ServerService.confirmKeyDialogResponse:" + data.fingerprint);

                context.broadcasts.sendBroadcast(new Intent("MainActivity.showConfirmKeyDialog").putExtra("fingerprint", data.fingerprint));
            }
        } catch (JSONException e) {
            Log.d(TAG, "[" + data.id + "] Closing: Got invalid public key");
            data.close();
        }
    }

    static void HandleHandshakeResponse(ServerService context, Packet packet, SocketData data) {
        // Allow this only if we just sent a challenge and haven't received a response yet
        if (data.state != CHALLENGE_SENT) {
            data.close();
            Log.d(TAG, "[" + data.id + "] Closing: Got C2S_HANDSHAKE_PUBLIC_KEY but state isn't CHALLENGE_SENT");
            return;
        }

        try {
            String challenge = packet.getPayload().getString("challenge");
            String signature = packet.getPayload().getString("signature");

            Log.d(TAG, "[" + data.id + "] Got handshake response: " + challenge + " and requested challenge: " + data.challenge + " and signature: " + signature);
            // Close if we got a different challenge than we sent.
            //
            // This blocks out man in the middle attacks as the challenge consists of <server id>:<random part>
            // where the server id is similarly to the fingerprint a SHA256 (for added security) hash of our certificate that is encoded as Base64.
            // We send our id but the client uses the id it sees.
            if (!challenge.equals(data.challenge)) {
                data.close();
                Log.d(TAG, "[" + data.id + "] Closing: Response challenge isn't sent challenge (hint: man in the middle detected)");
                return;
            }

            // Check if the signature was ok. If so, respond with a handshake OK, otherwise close the socket
            boolean signatureOK = SecurityHelper.verifySignature(challenge.getBytes(), Base64.decode(signature, Base64.NO_WRAP), data.publicKey);
            Log.d(TAG, "[" + data.id + "] Signature: " + (signatureOK ? "OK" : "Invalid"));
            if (signatureOK) {
                data.state = AUTHORIZED;
                data.send(S2C_HANDSHAKE_OK, new JSONObject());
                context.authorizedSockets.put(data.id, data);
                context.updateNotification();
            } else {
                data.close();
                Log.d(TAG, "[" + data.id + "] Closing: Invalid signature");
            }
        } catch(JSONException e) {
            Log.d(TAG, "[" + data.id + "] Closing: Got invalid payload");
            data.close();
        }
    }

    // Send a challenge to the socket
    static void sendChallenge(ServerService context, SocketData data) {
        try {
            // Generate the random part of the challenge
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);

            // See above for challenge details
            data.challenge = context.serverID + ":" + Base64.encodeToString(bytes, Base64.NO_WRAP);

            JSONObject json = new JSONObject();
            json.put("challenge", data.challenge);

            data.send(S2C_HANDSHAKE_CHALLENGE, json);
            data.state = CHALLENGE_SENT;
            Log.d(TAG, "[" + data.id + "] Sent challenge: " + data.challenge);
        } catch (Exception e) {
            data.close();
            Log.d(TAG, "[" + data.id + "] Closing: " + e.toString());
        }
    }

}
