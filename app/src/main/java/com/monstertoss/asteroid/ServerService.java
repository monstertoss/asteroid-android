package com.monstertoss.asteroid;

import android.app.IntentService;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.BitmapFactory;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.PowerManager;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.NotificationCompat;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.monstertoss.asteroid.MessageOpcode.*;
import static com.monstertoss.asteroid.SocketState.*;

public class ServerService extends IntentService {

    private static String TAG = "ServerService";

    private static byte[] WHO = {0x49,0x4c,0x7b,(byte)0xae,0x30,0x30,0x69,(byte)0x9e};
    private static byte[] HERE = {0x22,(byte)0xd6,(byte)0xb1,0x4b,0x35,0x28,0x10,0x51};

    private SharedPreferences preferences;

    private KeyPair keyPair;
    private Certificate certificate;
    private String serverID;
    private String serverFingerprint;

    private boolean shouldServerBeRunning = true;

    private ServerSocket serverSocket;
    private DatagramSocket udpServerSocket;

    private HashMap<String, SocketData> sockets = new HashMap<>();
    private HashMap<String, SocketData> authorizedSockets = new HashMap<>();
    private HashMap<String, Thread> threads = new HashMap<>();

    private KeyDatabase keyDB;
    private Context context;

    public ServerService() {
        super("ServerService");
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        // Initialize the server, open the database, load the server keys or generate a new keypair if there are no keys yet.
        Log.v(TAG, "Starting server...");
        context = this;

        // Make sure the system doesn't stop the server easily
        startForeground(1, buildNotification(0));

        // Acquire wifi locks
        WifiManager.WifiLock wifiLock = ((WifiManager)getApplicationContext().getSystemService(Context.WIFI_SERVICE)).createWifiLock(WifiManager.WIFI_MODE_FULL, MainActivity.PACKAGE_NAME);
        wifiLock.acquire();
        WifiManager.MulticastLock multicastLock = ((WifiManager)getApplicationContext().getSystemService(Context.WIFI_SERVICE)).createMulticastLock(MainActivity.PACKAGE_NAME);
        multicastLock.acquire();

        keyDB = new KeyDatabase(this);

        preferences = getSharedPreferences(MainActivity.PACKAGE_NAME, MODE_PRIVATE);
        if(preferences.contains("keypair") && preferences.contains("certificate")) {
            loadKeys();
        } else {
            generateAndStoreKeys();
        }

        // Broadcast receiver for when the server should terminate itself.
        LocalBroadcastManager.getInstance(this).registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.d(TAG, "Received stop");

                shouldServerBeRunning = false;
                try {
                    serverSocket.close();
                    udpServerSocket.close();
                } catch(IOException e) {}
            }
        }, new IntentFilter("ServerService.stop"));

        try {
            // Open a new listening socket (TCP; unencrypted)
            serverSocket = new ServerSocket(8877);
            // Open a listening socket (UDP; unencrypted) for automagically detecting devices on the lan
            udpServerSocket = new DatagramSocket(8877, InetAddress.getByName("0.0.0.0"));
            udpServerSocket.setBroadcast(true);

            // Spawn a thread to handle UDP packets
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Log.v(TAG, "UDP Server online");

                        while (shouldServerBeRunning) {
                            byte[] bytes = new byte[128];
                            DatagramPacket packet = new DatagramPacket(bytes, bytes.length);
                            udpServerSocket.receive(packet);

                            if(!Arrays.equals(WHO, Arrays.copyOfRange(packet.getData(), 0, WHO.length)))
                                return;

                            String fingerprint = new String(Arrays.copyOfRange(packet.getData(), WHO.length, packet.getLength())).trim();

                            boolean isKeyKnown = keyDB.DoesFingerprintExist(fingerprint);

                            Log.d(TAG, "Got WHO packet from server: " + fingerprint + (isKeyKnown ? " (Known)" : " (Unknown)"));

                            byte[] nameBytes = (Build.MANUFACTURER + " " + Build.MODEL).getBytes();
                            byte[] sendData = new byte[HERE.length + 1 + nameBytes.length];

                            System.arraycopy(HERE, 0, sendData, 0, HERE.length);
                            sendData[HERE.length] = (byte)(isKeyKnown ? 0x02 : 0x01);
                            System.arraycopy(nameBytes, 0, sendData, HERE.length+1, nameBytes.length);

                            DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, packet.getAddress(), packet.getPort());
                            udpServerSocket.send(sendPacket);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        Log.v(TAG, "UDP Server offline");
                        shouldServerBeRunning = false;
                        try {
                            serverSocket.close();
                        } catch(IOException e) {}
                    }
                }
            }, "UDP").start();

            while (shouldServerBeRunning) {
                try {
                    // wait until someone connect and accept that connection
                    final Socket socket = serverSocket.accept();

                    // This object holds various data about a connection: A unique id, the socket itself, its authentication state, the client's public key, the challenge sent to the client and the socket IO
                    final SocketData data = new SocketData(socket);

                    Log.v(TAG, "[" + data.id + "] Accepted connection");

                    // Spawn a new thread to handle that network connection and add both the socket data and the thread to the list of all connected sockets
                    Thread thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                // Pipe the socket's input and output through bouncy castle's tls protocol and set the new IO streams.
                                TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
                                DefaultTlsServer tlsServer = new DefaultTlsServer() {
                                    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
                                        return new DefaultTlsSignerCredentials(context, certificate, PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));
                                    }
                                };
                                tlsServerProtocol.accept(tlsServer);

                                data.inputStream = new BufferedInputStream(tlsServerProtocol.getInputStream());
                                data.outputStream = new BufferedOutputStream(tlsServerProtocol.getOutputStream());

                                // Spawn an IO thread that handles reading from the socket and writing whole packets to the buffer
                                new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Log.d(TAG, "[" + data.id + "] Started IO thread");
                                        ArrayList<Byte> buf = new ArrayList<>();
                                        while(shouldServerBeRunning && data.shouldBeRunning) {
                                            try {
                                                // Read all available data (without blocking) or 16 bytes, if no information is available
                                                int available = data.inputStream.available();
                                                available = (available > 0 ? available : 16);

                                                byte[] bytes = new byte[available];
                                                data.inputStream.read(bytes);

                                                // Iterate over every read byte, add it to the buffer and send that buffer to the main thread on a line break ('\n')
                                                for (byte b : bytes) {
                                                    buf.add(b);
                                                    if (b == '\n') {
                                                        data.inputBuffer.add(buf);
                                                        buf = new ArrayList<>();
                                                    }
                                                }
                                            } catch(IOException e) {
                                                // Trigger cleanup if an error occurs (socket was closed);
                                                data.shouldBeRunning = false;
                                                Log.d(TAG, "[" + data.id + "] Closing: " + e.toString());
                                            }
                                        }
                                        Log.d(TAG, "[" + data.id + "] Stopped IO thread");
                                    }
                                }, "IO:" + data.id).start();

                                while (shouldServerBeRunning && data.shouldBeRunning) {
                                    // Check if we received packet(s) and process
                                    if(data.inputBuffer.size() > 0) {
                                        for (ArrayList<Byte> msg : data.inputBuffer) {
                                            // Convert to byte[]
                                            byte[] bytes = new byte[msg.size()];
                                            for (int i = 0; i < msg.size(); i++) {
                                                bytes[i] = msg.get(i);
                                            }

                                            // Packets are built like that
                                            // 1 byte opcode, is any of the MessageOpcode enum
                                            // Base64 encoded JSON body
                                            // A linebreak ('\n') as delimiter

                                            // Parse opcode
                                            byte op = bytes[0];
                                            MessageOpcode opCode = MessageOpcode.from(op);
                                            if (opCode == null) {
                                                Log.v(TAG, "[" + data.id + "] Got invalid opcode: " + bytes[0]);
                                                shouldServerBeRunning = false;
                                                return;
                                            }

                                            // parse Json
                                            byte[] message = Base64.decode(bytes, 1, bytes.length - 1, Base64.NO_WRAP);
                                            String json = new String(message, "UTF-8");
                                            Log.d(TAG, "[" + data.id + "] Got message with opcode: " + bytes[0] + " and content: " + json);

                                            handleMessage(opCode, new JSONObject(json), data);
                                        }
                                        // Make sure that we aren't handling a packet twice
                                        data.inputBuffer = new ArrayList<>();
                                    }

                                    // Check if we have anything to write to the client
                                    if(data.outputBuffer.size() > 0) {
                                        for (ArrayList<Byte> message : data.outputBuffer) {
                                            for (Byte b : message) {
                                                // This only queues for sending (unless the stream has too much data in which case a package fragment is sent. The client is expected to handle that just as we do)
                                                data.outputStream.write(b);
                                            }
                                        }
                                        data.outputBuffer = new ArrayList<>();
                                        // Force sending
                                        data.outputStream.flush();
                                    }

                                    // Wait 128ms not to be too CPU intensive.
                                    synchronized (this) {
                                        wait(128);
                                    }
                                }
                            } catch(Exception e) {
                                Log.d(TAG, "[" + data.id + "] Closing: " + e.toString());
                            } finally {
                                // If an error occured, or we received a cleanup signal, make sure to send the cleanup signal and clean up.
                                data.shouldBeRunning = false;
                                Log.d(TAG, "[" + data.id + "] Closing connection");
                                try {
                                    if(!socket.isClosed())
                                       socket.close();
                                } catch (IOException exception) {}
                                if(data.publicKey != null) {
                                    LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("MainActivity.dismissConfirmKeyDialog:" + data.fingerprint));
                                }
                                sockets.remove(data.id);
                                threads.remove(data.id);

                                if(data.state == AUTHORIZED)
                                    authorizedSockets.remove(data.id);

                                // Update number of connected devices
                                startForeground(1, buildNotification(authorizedSockets.size()));
                            }
                        }
                    }, "Socket:" + data.id);
                    threads.put(data.id, thread);
                    sockets.put(data.id, data);
                    thread.start();
                } catch (IOException e) {}
            }
        } catch (IOException e) {
        } finally {
            // If an error occured or we received a stop server signal
            Log.d(TAG, "Stopping server...");
            // Close all connected sockets (cleanup is done afterwards)
            for(Map.Entry<String, SocketData> entry : sockets.entrySet()) {
                SocketData data = entry.getValue();
                try {
                    data.socket.close();
                } catch(IOException exception) {}
            }
            // Close the key database
            keyDB.close();
            // Release the wifi locks
            wifiLock.release();
            multicastLock.release();
            // Notify the UI
            LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent("MainActivity.stopped"));

            // Terminate the running service
            stopSelf();
        }
    }

    // Handle a syntactically correct package
    private void handleMessage(MessageOpcode opCode, JSONObject message, final SocketData data) {
        try {
            switch (opCode) {
                // The client sent its public key
                case C2S_HANDSHAKE_PUBLIC_KEY:
                    // Allow only if the client is yet unknown (allow this operation only once)
                    if(data.state != UNKNOWN) {
                        data.shouldBeRunning = false;
                        Log.d(TAG, "[" + data.id + "] Closing: Got C2S_HANDSHAKE_PUBLIC_KEY but state isn't UNKNOWN");
                        return;
                    }

                    // Decode the public key
                    final String keyString = message.getString("key");
                    byte[] key = Base64.decode(keyString, Base64.NO_WRAP);
                    data.publicKey = SecurityHelper.byteArrayToPublicKey(key);

                    // Close the socket if an invalid public key was sent
                    if (data.publicKey == null) {
                        Log.d(TAG, "[" + data.id + "] Closing: Got invalid public key");
                        data.shouldBeRunning = false;
                        return;
                    }
                    // Compute the key's fingerprint.
                    data.fingerprint = SecurityHelper.calculateFingerprint(data.publicKey.getEncoded());

                    Log.d(TAG, "[" + data.id + "] Received public key: " + data.fingerprint);

                    // Query our database
                    if (keyDB.DoesFingerprintExist(data.fingerprint)) {
                        // Client is known, proceed to sending a challenge
                        data.state = KNOWN_PUBLIC_KEY;
                        data.send(S2C_HANDSHAKE_PUBLIC_KEY_KNOWN, new JSONObject());

                        sendChallenge(data);
                    } else {
                        // Notify UI to show a popup to confirm this client
                        data.state = UNKNOWN_PUBLIC_KEY;
                        data.send(S2C_HANDSHAKE_PUBLIC_KEY_UNKNOWN, new JSONObject());

                        // Broadcast receiver after either OK or Cancel is clicked in the UI
                        LocalBroadcastManager.getInstance(this).registerReceiver(new BroadcastReceiver() {
                            @Override
                            public void onReceive(Context context, Intent intent) {
                                LocalBroadcastManager.getInstance(context).unregisterReceiver(this);
                                boolean confirmed = intent.getBooleanExtra("confirmed", false);

                                Log.v(TAG, "[" + data.id + "] " + (confirmed ? "Rejected" : "Confirmed") + " key: " + data.fingerprint);

                                // If the key was confirmed, store that in our database and proceed with sending a challenge, otherwise close the socket.
                                if (confirmed) {
                                    keyDB.PutKey(keyString, data.fingerprint);
                                    data.state = KNOWN_PUBLIC_KEY;
                                    data.send(S2C_HANDSHAKE_PUBLIC_KEY_KNOWN, new JSONObject());

                                    sendChallenge(data);
                                } else {
                                    data.shouldBeRunning = false;
                                    Log.d(TAG, "[" + data.id + "] Closing: Public key rejected by user");
                                }
                            }
                        }, new IntentFilter("ServerService.confirmKeyDialogResponse:" + data.fingerprint));

                        LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent("MainActivity.showConfirmKeyDialog").putExtra("fingerprint", data.fingerprint));
                    }
                    break;

                // The client sent a response to our challenge
                case C2S_HANDSHAKE_RESPONSE:
                    // Allow this only if we just sent a challenge and haven't received a response yet
                    if(data.state != CHALLENGE_SENT) {
                        data.shouldBeRunning = false;
                        Log.d(TAG, "[" + data.id + "] Closing: Got C2S_HANDSHAKE_PUBLIC_KEY but state isn't CHALLENGE_SENT");
                        return;
                    }

                    String challenge = message.getString("challenge");
                    String signature = message.getString("signature");

                    Log.d(TAG, "[" + data.id + "] Got handshake response: " + challenge + " and requested challenge: " + data.challenge + " and signature: " + signature);
                    // Close if we got a different challenge than we sent.
                    //
                    // This blocks out man in the middle attacks as the challenge consists of <server id>:<random part>
                    // where the server id is similarly to the fingerprint a SHA256 (for added security) hash of our certificate that is encoded as Base64.
                    // We send our id but the client uses the id it sees.
                    if(!challenge.equals(data.challenge)) {
                        data.shouldBeRunning = false;
                        Log.d(TAG, "[" + data.id + "] Closing: Response challenge isn't sent challenge (hint: man in the middle detected)");
                        return;
                    }

                    // Check if the signature was ok. If so, respond with a handshake OK, otherwise close the socket
                    boolean signatureOK = SecurityHelper.verifySignature(challenge.getBytes(), Base64.decode(signature, Base64.NO_WRAP), data.publicKey);
                    Log.d(TAG, "[" + data.id + "] Signature: " + (signatureOK ? "OK" : "Invalid"));
                    if(signatureOK) {
                        data.state = AUTHORIZED;
                        data.send(S2C_HANDSHAKE_OK, new JSONObject());
                        authorizedSockets.put(data.id, data);
                        startForeground(1, buildNotification(authorizedSockets.size()));
                    } else {
                        data.shouldBeRunning = false;
                        Log.d(TAG, "[" + data.id + "] Closing: Invalid signature");
                    }
                    break;
            }
        } catch(Exception e) {
            // Close the socket if any exception occurs, for example malformed messages
            data.shouldBeRunning = false;
            Log.d(TAG, "[" + data.id + "] Closing: " + e.toString());
        }
    }

    // Send a challenge to the socket
    private void sendChallenge(SocketData data) {
        try {
            // Generate the random part of the challenge
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);

            // See above for challenge details
            data.challenge = serverID + ":" + Base64.encodeToString(bytes, Base64.NO_WRAP);

            JSONObject json = new JSONObject();
            json.put("challenge", data.challenge);

            data.send(S2C_HANDSHAKE_CHALLENGE, json);
            data.state = CHALLENGE_SENT;
            Log.d(TAG, "[" + data.id + "] Sent challenge: " + data.challenge);
        } catch(Exception e) {
            data.shouldBeRunning = false;
            Log.d(TAG, "[" + data.id + "] Closing: " + e.toString());
        }
    }

    // Load keys from the shared preferences
    private void loadKeys() {
        try {
            String encodedKeyPair = preferences.getString("keypair", "");
            String encodedCertificate = preferences.getString("certificate", "");

            Log.d(TAG, "Loading keys... KeyPair: " + encodedKeyPair.substring(0, 16) + "... Certificate: " + encodedCertificate.substring(0, 16) + "...");

            // Deserialize keypair and certificate
            keyPair = (KeyPair) new ObjectInputStream(new ByteArrayInputStream(Base64.decode(encodedKeyPair, Base64.NO_WRAP))).readObject();
            certificate = Certificate.parse(new ByteArrayInputStream(Base64.decode(encodedCertificate, Base64.NO_WRAP)));

            if(certificate.getCertificateAt(0).getEndDate().getDate().before(new Date()))
                generateAndStoreKeys();
            else
                calculateIDAndFingerprint();

        } catch(Exception e) {
            e.printStackTrace();
            // Generate a new keypair if loading failed
            generateAndStoreKeys();
        }
    }

    private void generateAndStoreKeys() {
        Log.d(TAG, "Generating keys...");
        try {
            // Generate the keypair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Calculate expiry date for the certificate
            long now = System.currentTimeMillis();
            Date startDate = new Date(now);

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(startDate);
            calendar.add(Calendar.YEAR, 1); // <-- 1 Year validity

            Date endDate = calendar.getTime();

            String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

            // Use bouncy castle to create a self signed certificate
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name("cn=" + getString(R.string.app_name)), new BigInteger(Long.toString(now)), startDate, endDate, new X500Name("cn=" + getString(R.string.app_name)), keyPair.getPublic());
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, new BasicConstraints(true)); // Basic Constraints is usually marked as critical.
            Certificate certificate = new Certificate(new org.bouncycastle.asn1.x509.Certificate[]{certBuilder.build(contentSigner).toASN1Structure()});

            // Serialize keypair
            ByteArrayOutputStream keyPairStream = new ByteArrayOutputStream();
            new ObjectOutputStream(keyPairStream).writeObject(keyPair);
            String encodedKeyPair = Base64.encodeToString(keyPairStream.toByteArray(), Base64.NO_WRAP);

            // Serialize certificate
            ByteArrayOutputStream certificateStream = new ByteArrayOutputStream();
            certificate.encode(certificateStream);
            String encodedCertificate = Base64.encodeToString(certificateStream.toByteArray(), Base64.NO_WRAP);

            // Store keypair and certificate
            preferences.edit().putString("certificate", encodedCertificate).putString("keypair", encodedKeyPair).apply();

            this.keyPair = keyPair;
            this.certificate = certificate;
            calculateIDAndFingerprint();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    public void calculateIDAndFingerprint() {
        try {
            serverID = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getCertificateAt(0).getEncoded()), Base64.NO_WRAP);
            serverFingerprint = SecurityHelper.calculateFingerprint(certificate.getCertificateAt(0).getEncoded());
            Log.d(TAG, "Loaded key " + serverFingerprint + " (server id: " + serverID + ")");
        } catch(Exception e) {}
    }

    private Notification buildNotification(int numberOfDevices) {
        PendingIntent contentIntent = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), 0);
        String notificationText = getString(R.string.asteroidIsRunning);
        return new NotificationCompat.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setLargeIcon(BitmapFactory.decodeResource(getResources(), R.mipmap.ic_launcher))
                .setTicker(notificationText)
                .setContentTitle(notificationText)
                .setContentText(getResources().getQuantityString(R.plurals.notificationText, numberOfDevices, numberOfDevices))
                .setContentIntent(contentIntent)
                .setChannelId(MainActivity.NOTIFICATION_CHANNEL)
                .build();
    }

}
