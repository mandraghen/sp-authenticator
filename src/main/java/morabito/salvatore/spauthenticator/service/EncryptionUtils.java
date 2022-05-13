package morabito.salvatore.spauthenticator.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface EncryptionUtils {
    String createSha256Digest(byte[] data);

    PrivateKey createPrivateKey(String cleanedKey) throws NoSuchAlgorithmException, InvalidKeySpecException;

    String cleanPKString(StringBuilder keyString);

    String signWithRsaSha256(String signatureString, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException;
}
