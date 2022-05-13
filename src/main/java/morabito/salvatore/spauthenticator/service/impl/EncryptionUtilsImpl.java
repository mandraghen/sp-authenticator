package morabito.salvatore.spauthenticator.service.impl;

import lombok.extern.java.Log;
import morabito.salvatore.spauthenticator.service.EncryptionUtils;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;

@Service
@Log
public class EncryptionUtilsImpl implements EncryptionUtils {

    public String createSha256Digest(byte[] data) {
        if (data == null) {
            data = new byte[]{};
        }

        try {
            byte[] hashedData = hashData(data);
            String digestHeader = "SHA-256=" + Base64.getEncoder().encodeToString(hashedData);
            log.info("Created digest header: " + digestHeader);
            return digestHeader;
        } catch (NoSuchAlgorithmException e) {
            log.log(Level.SEVERE, "Error retrieving sha-256 digester", e);
        }

        return "";
    }

    private byte[] hashData(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digester = MessageDigest.getInstance("SHA-256");
        digester.update(data);
        return digester.digest();
    }

    public PrivateKey createPrivateKey(String cleanedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(cleanedKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public String cleanPKString(StringBuilder keyString) {
        return keyString.toString().replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("\n", "");
    }

    public String signWithRsaSha256(String signatureString, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(signatureString.getBytes(StandardCharsets.UTF_8));
        byte[] digitalSignature = privateSignature.sign();
        String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);
        log.info("Signature string encoded successfully: " + encodedSignature);
        return encodedSignature;
    }
}
