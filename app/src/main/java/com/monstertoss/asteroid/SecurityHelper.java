package com.monstertoss.asteroid;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.StringReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Formatter;

// Helper class for multiple security functions
public class SecurityHelper {
    // Convert PEM key to RSAPublicKey (PublicKey)
    public static RSAPublicKey byteArrayToPublicKey(byte[] key) {
        try {
            PEMParser pemParser = new PEMParser(new StringReader(new String(key)));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return (RSAPublicKey) converter.getPublicKey((SubjectPublicKeyInfo)pemParser.readObject());
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Calculate a certificate fingerprint. This is also used for raw public keys so the client does not need a self signed certificate (a public key is enough) (**NOT** PEM, DER format)
    public static String calculateFingerprint(byte[] cert) {
        byte[] fingerprint;
        try {
            fingerprint = MessageDigest.getInstance("SHA-1").digest(cert);
        } catch(NoSuchAlgorithmException e) {
            return "";
        }
        Formatter formatter = new Formatter();
        for (byte b : fingerprint) {
            formatter.format("%02x:", b);
        }
        String hex = formatter.toString();
        return hex.substring(0, hex.length()-1).toUpperCase();
    }

    // Verify a signature. message is the String bytes, signature the raw signature (sent as Base64 across the wire)
    public static boolean verifySignature(byte[] message, byte[] signature, RSAPublicKey publicKey) {
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(false, new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent()));
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }

}
