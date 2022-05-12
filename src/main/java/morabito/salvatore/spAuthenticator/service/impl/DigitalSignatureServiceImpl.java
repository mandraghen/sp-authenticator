package morabito.salvatore.spAuthenticator.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import morabito.salvatore.spAuthenticator.constant.Constants;
import morabito.salvatore.spAuthenticator.service.DigitalSignatureService;
import morabito.salvatore.spAuthenticator.service.EncryptionUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.BinaryOperator;
import java.util.function.Consumer;
import java.util.logging.Level;

@RequiredArgsConstructor
@Log
@Service
public class DigitalSignatureServiceImpl implements DigitalSignatureService {

    @Value("${sp.encrypt.signature.keyid}")
    private String keyId;
    @Value("${sp.encrypt.privatekey.path}")
    private String privateKeyPath;

    private final EncryptionUtils encryptionUtils;

    @Override
    public HttpHeaders createSignHeaders(String destinationUrl, HttpMethod httpMethod,
                                                 HttpHeaders requestHeaders, byte[] body) {
        var signHeaders = new HttpHeaders();
        //add headers
        signHeaders.put("Date", Collections.singletonList(createDateForHeader()));
        //add digest for empty body
        signHeaders.put("Digest", Collections.singletonList(encryptionUtils.createSha256Digest(body)));
        //add Authorization header
        signHeaders.put("Authorization", Collections.singletonList(
                createAuthenticationHeader(destinationUrl, httpMethod, requestHeaders)));

        return signHeaders;
    }

    private String createAuthenticationHeader(String destinationUrl, HttpMethod httpMethod,
                                              HttpHeaders requestHeaders) {
        //Authorization: Signature keyId="Test", algorithm="hmac-sha256", headers="(request-target) host date digest",
        // signature="ATp0r26dbMIxOopqw0O.........", satispaysequence="4", satispayperformance="LOW"
        StringBuilder authHeader = new StringBuilder();
        //put the signature in a property
        authHeader.append("Signature keyId=\"").append(keyId).append("\", ");
        authHeader.append("algorithm=\"rsa-sha256\", ");
        appendHeaders(requestHeaders, authHeader);
        authHeader.append(", signature=\"").append(createSignature(destinationUrl, httpMethod, requestHeaders)).append("\", ");
//        authHeader.append("satispayresign=\"enable\"");

        log.info("Authorization header: " + authHeader);

        return authHeader.toString();
    }

    private final BinaryOperator<String> getStringBinaryOperator = (s1, s2) -> s1 + s2;

    private void appendHeaders(HttpHeaders requestHeaders, StringBuilder authHeader) {
        authHeader.append("headers=\"(request-target)");

        requestHeaders.keySet().stream()
                .sequential()
                .map(header -> " " + header.toLowerCase())
                .reduce(getStringBinaryOperator)
                .ifPresent(getStringConsumer(authHeader));

//        requestHeaders.map().keySet().stream()
//                .reduce(getStringBinaryOperator)
//                .ifPresent(getStringConsumer(authHeader));

//        Arrays.stream(httpMethod.getHeaders())
//                .sequential()
//                .map(header -> { return " " + header.getName().toLowerCase(); })
//                .reduce(getStringBinaryOperator)
//                .ifPresent(getStringConsumer(authHeader));

        authHeader.append("\"");

        log.info("Authorization after appending headers: " + authHeader);
    }

    private Consumer<String> getStringConsumer(StringBuilder authHeader) {
        return authHeader::append;
    }

    private String createDateForHeader() {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat(Constants.DATE_PATTERN_FOR_HEADER, Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        String date = dateFormat.format(calendar.getTime());
        log.info("Created date string for header: " + date);

        return date;
    }

    private String createSignature(String destinationUrl, HttpMethod httpMethod,
                                   HttpHeaders requestHeaders) {
        //create signature String
        String requestTargetParameter = createRequestTargetParameter(destinationUrl, httpMethod);
        String signatureString = createSignatureString(requestTargetParameter, requestHeaders);
        try {
            PrivateKey privateKey = getPrivateKey();

            if (privateKey != null) {
                return encryptionUtils.signWithRsaSha256(signatureString, privateKey);
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.log(Level.SEVERE, "Error signing signature string", e);
        }
        return null;
    }

    private String createSignatureString(String requestTargetParameter, HttpHeaders requestHeaders) {

        StringBuilder signatureString = new StringBuilder(requestTargetParameter);
        //TODO
        /* If there are multiple instances of the same header field, all header field values associated with the header
           field MUST be concatenated, separated by a ASCII comma and an ASCII space ,, and used in the order in which
           they will appear in the transmitted HTTP message.
         */
        requestHeaders.forEach((key, value) -> signatureString.append("\n")
                .append(key.toLowerCase())
                .append(Constants.HEADER_KEY_SEPARATOR)
                .append(value.stream()
                        .reduce((s1, s2) -> s1 + ", " + s2)));

//        Arrays.stream(httpMethod.getHeaders())
//                .sequential()
//                .map(header -> {
//                    return "\n" + header.getName().toLowerCase() + Constants.HEADER_KEY_SEPARATOR +
//                            header.getValue().trim();
//                })
//                .reduce((s1, s2) -> s1 + s2)
//                .ifPresent(s -> {
//                    signatureString.append(s);
//                });
        log.info("Signature string: " + signatureString);

        return signatureString.toString();
    }

    private String createRequestTargetParameter(String destinationUrl, HttpMethod httpMethod) {
        String headerString = Constants.REQUEST_TARGET_HEADER + Constants.HEADER_KEY_SEPARATOR +
                httpMethod.name().toLowerCase() + " " + destinationUrl;
        log.info("Created request-target parameter: " + headerString);
        return headerString;
    }

    private PrivateKey getPrivateKey() {
        InputStream pkStream = ClassLoader.getSystemResourceAsStream(privateKeyPath);

        try (BufferedReader reader = new BufferedReader((new InputStreamReader(pkStream)))) {
            StringBuffer keyString = new StringBuffer();
            String line;
            while ((line = reader.readLine()) != null) {
                keyString.append(line);
            }
            reader.close();

            String cleanedKey = encryptionUtils.cleanPKString(keyString);
            return encryptionUtils.createPrivateKey(cleanedKey);
        } catch (FileNotFoundException e) {
            log.log(Level.SEVERE, "Can't find file in: " + privateKeyPath, e);
        } catch (NoSuchAlgorithmException e) {
            log.log(Level.SEVERE, "Algorithm not found: RSA", e);
        } catch (IOException e) {
            log.log(Level.SEVERE, "Error closing file streams ", e);
        } catch (InvalidKeySpecException e) {
            log.log(Level.SEVERE, "Invalid key specification", e);
        }
        return null;
    }
}
