package com.monstertoss.asteroid;

import android.app.IntentService;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.BitmapFactory;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Looper;
import android.support.v7.app.NotificationCompat;
import android.util.Base64;
import android.util.Log;

import com.monstertoss.zstd_android.ZstdInputStream;
import com.monstertoss.zstd_android.ZstdOutputStream;

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
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
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

    private static final String TAG = "ServerService";

    static final byte[] WHO = {0x49, 0x4c, 0x7b, (byte) 0xae, 0x30, 0x30, 0x69, (byte) 0x9e};
    static final byte[] HERE = {0x22, (byte) 0xd6, (byte) 0xb1, 0x4b, 0x35, 0x28, 0x10, 0x51};

    SharedPreferences preferences;

    KeyPair keyPair;
    Certificate certificate;
    String serverID;
    String serverFingerprint;

    private ServerSocket serverSocket;
    private DatagramSocket udpServerSocket;

    HashMap<String, SocketData> sockets = new HashMap<>();
    HashMap<String, SocketData> authorizedSockets = new HashMap<>();
    private HashMap<String, Thread> allThreads = new HashMap<>();

    KeyDatabase keyDB;

    BroadcastHelper broadcasts;

    private WifiManager.WifiLock wifiLock;
    private WifiManager.MulticastLock multicastLock;

    public ServerService() {
        super("ServerService");
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        // Initialize the server, open the database, load the server keys or generate a new keypair if there are no keys yet.
        Log.v(TAG, "Starting server...");

        // Make sure the system doesn't stop the server easily
        startForeground(1, buildNotification(0));

        // Initialize our helpers
        keyDB = new KeyDatabase(this);
        broadcasts = new BroadcastHelper(this);

        preferences = getSharedPreferences(getPackageName(), MODE_PRIVATE);
        if (preferences.contains("keypair") && preferences.contains("certificate")) {
            loadKeys();
        } else {
            generateAndStoreKeys();
        }

        // Acquire wifi locks
        wifiLock = ((WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE)).createWifiLock(WifiManager.WIFI_MODE_FULL, getPackageName());
        wifiLock.acquire();

        multicastLock = ((WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE)).createMulticastLock(getPackageName());
        multicastLock.acquire();

        // Broadcast receiver for when the server should terminate itself.
        broadcasts.addBroadcastListener(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.d(TAG, "Received stop");

                stopServer();
                stopSelf();
            }
        }, "ServerService.stop");

        startServer();
    }


    @Override
    public void onDestroy() {
        super.onDestroy();

        // This method is the last call that this service gets, cleaning up
        Log.d(TAG, "Received onDestroy()...");


        stopServer();

        // Close the key database
        keyDB.close();
        // Release the wifi locks
        if (wifiLock != null)
            wifiLock.release();
        if (multicastLock != null)
            multicastLock.release();

        // Notify the UI and clean up broadcasts
        broadcasts.sendBroadcast("MainActivity.stopped");
        broadcasts.removeAllBroadcastListeners();
    }

    private void stopServer() {
        for (Map.Entry<String, Thread> entry : allThreads.entrySet()) {
            Thread thread = entry.getValue();
            thread.interrupt();
            if(sockets.containsKey(entry.getKey()))
                sockets.get(entry.getKey()).close();
        }

        try {
            serverSocket.close();
            udpServerSocket.close();
        } catch (IOException e) {}
    }

    private void startServer() {
        try {
            // Open a new listening socket (TCP; unencrypted)
            serverSocket = new ServerSocket(8877);
            // Open a listening socket (UDP; unencrypted) for automagically detecting devices on the lan
            udpServerSocket = new DatagramSocket(8877, InetAddress.getByName("0.0.0.0"));
            udpServerSocket.setBroadcast(true);

            // Spawn a thread to handle UDP packets
            Thread udp = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Log.v(TAG, "UDP Server online");

                        while (!Thread.interrupted()) {
                            try {
                                byte[] bytes = new byte[128];
                                DatagramPacket packet = new DatagramPacket(bytes, bytes.length);
                                udpServerSocket.receive(packet);

                                if (!Arrays.equals(WHO, Arrays.copyOfRange(packet.getData(), 0, WHO.length)))
                                    continue;

                                String fingerprint = new String(Arrays.copyOfRange(packet.getData(), WHO.length, packet.getLength())).trim();

                                boolean isKeyKnown = keyDB.DoesFingerprintExist(fingerprint);

                                Log.d(TAG, "Got WHO packet from server: " + fingerprint + (isKeyKnown ? " (Known)" : " (Unknown)"));

                                byte[] nameBytes = (Build.MANUFACTURER + " " + Build.MODEL).getBytes();
                                byte[] sendData = new byte[HERE.length + 1 + nameBytes.length];

                                System.arraycopy(HERE, 0, sendData, 0, HERE.length);
                                sendData[HERE.length] = (byte) (isKeyKnown ? 0x02 : 0x01);
                                System.arraycopy(nameBytes, 0, sendData, HERE.length + 1, nameBytes.length);

                                DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, packet.getAddress(), packet.getPort());
                                udpServerSocket.send(sendPacket);
                            } catch (IOException e) {
                                Log.w(TAG, "UDP: IOException: " + e.getMessage());
                                throw new InterruptedIOException(e.getMessage());
                            }
                        }
                        throw new InterruptedException();

                    } catch (InterruptedException | InterruptedIOException e) {
                        Log.v(TAG, "UDP Server offline");
                        if (!udpServerSocket.isClosed())
                            udpServerSocket.close();

                        allThreads.remove("UDP");
                        stopServer();
                    }
                }
            }, "UDP");
            udp.start();
            allThreads.put("UDP", udp);

            while (true) {
                // wait until someone connect and accept that connection
                final Socket socket = serverSocket.accept();

                // This object holds various data about a connection: A unique id, the socket itself, its authentication state, the client's public key, the challenge sent to the client and the socket IO
                final SocketData data = new SocketData(socket);

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

                Log.v(TAG, "[" + data.id + "] Accepting connection");

                // Spawn an IO thread that handles reading from the socket and writing whole packets to the buffer
                Thread IOThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.d(TAG, "[" + data.id + "] Started IO thread");

                        ArrayList<Byte> buf = new ArrayList<>();
                        try {
                            while (!Thread.interrupted()) {
                                try {
                                    // Read all available data (without blocking) or 16 bytes, if no information is available
                                    int available = data.inputStream.available();
                                    available = (available > 0 ? available : 16);

                                    byte[] bytes = new byte[available];
                                    int read = data.inputStream.read(bytes);

                                    // Iterate over every read byte, add it to the buffer and send that buffer to the main thread on a line break ('\n')
                                    for (int i = 0; i < read; i++) {
                                        byte b = bytes[i];
                                        if (buf.size() > Packet.MAX_PACKAGE_SIZE) {
                                            Log.d(TAG, "[" + data.id + "] Closing: Incoming message exceeded MAX_PACKAGE_SIZE (" + Packet.MAX_PACKAGE_SIZE + ") without sending a package delimiter.");
                                            data.close();
                                            return;
                                        }

                                        if (b == (byte) 0xFF) {
                                            byte[] packet = new byte[buf.size()];
                                            for (int j = 0; j < buf.size(); j++) {
                                                packet[j] = buf.get(j);
                                            }

                                            data.inputBuffer.add(new Packet(packet));
                                            buf = new ArrayList<>();
                                        } else
                                            buf.add(b);
                                    }
                                } catch(IOException e) {
                                    Log.w(TAG, "[" + data.id + "] IOException: " + e.getMessage());
                                    throw new InterruptedIOException(e.getMessage());
                                }
                            }
                            throw new InterruptedException();

                        } catch (InterruptedException | InterruptedIOException e) {
                            Log.d(TAG, "[" + data.id + "] Stopped IO thread");

                            allThreads.remove("IO:" + data.id);

                            if(allThreads.containsKey(data.id)) {
                                allThreads.get(data.id).interrupt();
                                sockets.get(data.id).close();
                            }
                        }
                    }
                }, "IO:" + data.id);
                IOThread.start();
                allThreads.put("IO:" + data.id, IOThread);

                // Spawn a new thread to handle that network connection and add both the socket data and the thread to the list of all connected sockets
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        // Why is that needed?
                        //Looper.prepare();

                        try {
                            while (!Thread.interrupted()) {
                                // Check if we received packet(s) and process
                                if (data.inputBuffer.size() > 0) {
                                    for (Packet packet : data.inputBuffer) {
                                        if (!packet.isValid()) {
                                            Log.v(TAG, "[" + data.id + "] Closing: Got invalid packet: " + packet);
                                            data.close();
                                            return;
                                        }

                                        handleMessage(packet, data);
                                    }
                                    // Make sure that we aren't handling a packet twice
                                    data.inputBuffer = new ArrayList<>();
                                }

                                // Check if we have anything to write to the client
                                if (data.outputBuffer.size() > 0) {
                                    try {
                                        for (Packet p : data.outputBuffer) {
                                            // This only queues for sending (unless the stream has too much data in which case a package fragment is sent. The client is expected to handle that just as we do)
                                            byte[] encoded = p.encodePayload();
                                            data.outputStream.write(p.getRawOpcode());
                                            data.outputStream.write(ByteBuffer.allocate(4).putInt(p.getRawPayload().getBytes().length).array());
                                            data.outputStream.write(encoded);
                                            data.outputStream.write((byte) 0xFF);
                                        }
                                        data.outputBuffer = new ArrayList<>();
                                        // Force sending
                                        data.outputStream.flush();
                                    } catch(IOException e) {
                                        Log.w(TAG, "[" + data.id + "] IOException: " + e.getMessage());
                                        throw new InterruptedIOException(e.getMessage());
                                    }
                                }

                                // Wait 128ms not to be too CPU intensive.
                                synchronized (this) {
                                    wait(128);
                                }
                            }
                            throw new InterruptedException();

                        } catch (InterruptedException | InterruptedIOException e) {
                            // If an error occurred, or we received a cleanup signal, make sure to send the cleanup signal and clean up.
                            Log.d(TAG, "[" + data.id + "] Closing connection");

                            allThreads.remove(data.id);

                            if(allThreads.containsKey("IO:" + data.id))
                                allThreads.get("IO:" + data.id).interrupt();

                            if (data.publicKey != null) {
                                broadcasts.sendBroadcast("MainActivity.dismissConfirmKeyDialog:" + data.fingerprint);
                            }

                            try {
                                if (!socket.isClosed())
                                    socket.close();
                            } catch(IOException io) {}

                            sockets.remove(data.id);

                            if (data.state == AUTHORIZED)
                                authorizedSockets.remove(data.id);

                            // Update number of connected devices
                            startForeground(1, buildNotification(authorizedSockets.size()));
                        }
                    }
                }, "Socket:" + data.id);
                allThreads.put(data.id, thread);
                sockets.put(data.id, data);
                data.thread = thread;
                thread.start();
            }
        } catch (IOException e) {
            stopServer();
            stopSelf();
        }
    }

    // Handle a syntactically correct package
    private void handleMessage(Packet packet, final SocketData data) {
        try {
            switch (packet.getOpCode()) {
                // The client sent its public key
                case C2S_HANDSHAKE_PUBLIC_KEY:
                    HandshakeHandler.HandlePublicKey(this, packet, data);
                    break;

                // The client sent a response to our challenge
                case C2S_HANDSHAKE_RESPONSE:
                    HandshakeHandler.HandleHandshakeResponse(this, packet, data);
                    break;

                case C2S_REQUEST_CONTACTS:
                    ContactsHandler.HandleRequestContacts(this, packet, data);
                    break;
            }
        } catch (Exception e) {
            // Close the socket if any exception occurs, for example malformed messages
            data.close();
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

            if (certificate.getCertificateAt(0).getEndDate().getDate().before(new Date()))
                generateAndStoreKeys();
            else
                calculateIDAndFingerprint();

        } catch (Exception e) {
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void calculateIDAndFingerprint() {
        try {
            serverID = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getCertificateAt(0).getEncoded()), Base64.NO_WRAP);
            serverFingerprint = SecurityHelper.calculateFingerprint(certificate.getCertificateAt(0).getEncoded());
            Log.d(TAG, "Loaded key " + serverFingerprint + " (server id: " + serverID + ")");
        } catch (Exception e) {
        }
    }

    public void updateNotification() {
        startForeground(1, buildNotification(authorizedSockets.size()));
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
                .setChannelId(getPackageName())
                .build();
    }

}
