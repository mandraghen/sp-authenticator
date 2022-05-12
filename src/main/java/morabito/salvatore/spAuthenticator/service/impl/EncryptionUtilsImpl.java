package morabito.salvatore.spAuthenticator.service.impl;

import morabito.salvatore.spAuthenticator.service.EncryptionUtils;
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
import java.util.logging.Logger;

@Service
public class EncryptionUtilsImpl implements EncryptionUtils {

    private final static Logger LOGGER = Logger.getLogger(EncryptionUtilsImpl.class.getName());

    public String createSha256Digest(byte[] data) {
        if (data == null) {
            data = new byte[]{};
        }

        try {
            byte[] hashedData = hashData(data);
            String digestHeader = "SHA-256=" + Base64.getEncoder().encodeToString(hashedData);
            LOGGER.info("Created digest header: " + digestHeader);
            return digestHeader;
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "Error retrieving sha-256 digester", e);
        }

//        return Constants.EMPTY_STRING;
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

    public String cleanPKString(StringBuffer keyString) {
        return keyString.toString().replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("\n", "");
    }

    public String signWithRsaSha256(String signatureString, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(signatureString.getBytes(StandardCharsets.UTF_8));
        byte[] digitalSignature = privateSignature.sign();
        String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);
        LOGGER.info("Signature string encoded successfully: " + encodedSignature);
        return encodedSignature;
    }
}
