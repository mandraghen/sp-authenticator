package morabito.salvatore.spauthenticator.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import morabito.salvatore.spauthenticator.constant.Constants;
import morabito.salvatore.spauthenticator.service.DigitalSignatureService;
import morabito.salvatore.spauthenticator.service.EncryptionUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
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
    public HttpHeaders createSignHeaders(String destinationUrl, String httpMethod,
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

    private String createAuthenticationHeader(String destinationUrl, String httpMethod,
                                              HttpHeaders requestHeaders) {
        //Authorization: Signature keyId="Test", algorithm="hmac-sha256", headers="(request-target) host date digest",
        // signature="ATp0r26dbMIxOopqw0O.........", satispaysequence="4", satispayperformance="LOW"
        var authHeader = new StringBuilder();
        //put the signature in a property
        authHeader.append("Signature keyId=\"").append(keyId).append("\", ")
                .append("algorithm=\"rsa-sha256\", ")
                .append(buildRequestTargetHeader(requestHeaders))
                .append(", signature=\"").append(
                        createSignature(destinationUrl, httpMethod, requestHeaders).orElse(""));

        log.info("Authorization header: " + authHeader);

        return authHeader.toString();
    }

     private static final BinaryOperator<String> getStringBinaryOperator = (s1, s2) -> s1 + s2;

    private String buildRequestTargetHeader(HttpHeaders requestHeaders) {
        var requestTargetHeader = new StringBuilder();
        requestTargetHeader.append("headers=\"(request-target)");

        requestHeaders.keySet().stream()
                .sequential()
                .map(header -> " " + header.toLowerCase())
                .reduce(getStringBinaryOperator)
                .ifPresent(getStringConsumer(requestTargetHeader));

        requestTargetHeader.append("\"");

        log.info("Authorization after appending headers: " + requestTargetHeader);
        return requestTargetHeader.toString();
    }

    private Consumer<String> getStringConsumer(StringBuilder authHeader) {
        return authHeader::append;
    }

    private String createDateForHeader() {
        var calendar = Calendar.getInstance();
        var dateFormat = new SimpleDateFormat(Constants.DATE_PATTERN_FOR_HEADER, Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        var date = dateFormat.format(calendar.getTime());
        log.info("Created date string for header: " + date);

        return date;
    }

    private Optional<String> createSignature(String destinationUrl, String httpMethod,
                                             HttpHeaders requestHeaders) {
        //create signature String
        String requestTargetParameter = createRequestTargetParameter(destinationUrl, httpMethod);
        String signatureString = createSignatureString(requestTargetParameter, requestHeaders);
        try {
            Optional<PrivateKey> privateKey = getPrivateKey();
            if (privateKey.isPresent()) {
                return Optional.of(encryptionUtils.signWithRsaSha256(signatureString, privateKey.get()));
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.log(Level.SEVERE, "Error signing signature string", e);
        }
        return Optional.empty();
    }

    private String createSignatureString(String requestTargetParameter, HttpHeaders requestHeaders) {

        var signatureString = new StringBuilder(requestTargetParameter);
        /* If there are multiple instances of the same header field, all header field values associated with the header
           field MUST be concatenated, separated by a ASCII comma and an ASCII space ,, and used in the order in which
           they will appear in the transmitted HTTP message.
         */
        requestHeaders.forEach((key, value) -> signatureString.append("\n")
                .append(key.toLowerCase())
                .append(Constants.HEADER_KEY_SEPARATOR)
                .append(value.stream()
                        .reduce((s1, s2) -> s1 + ", " + s2)));
        log.info("Signature string: " + signatureString);

        return signatureString.toString();
    }

    private String createRequestTargetParameter(String destinationUrl, String httpMethod) {
        String headerString = Constants.REQUEST_TARGET_HEADER + Constants.HEADER_KEY_SEPARATOR +
                httpMethod.toLowerCase() + " " + destinationUrl;
        log.info("Created request-target parameter: " + headerString);
        return headerString;
    }

    private Optional<PrivateKey> getPrivateKey() {
        Resource resource = new ClassPathResource(privateKeyPath);

        try (var reader = new BufferedReader((new InputStreamReader(resource.getInputStream())))) {
            var keyString = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                keyString.append(line);
            }

            String cleanedKey = encryptionUtils.cleanPKString(keyString);
            return Optional.of(encryptionUtils.createPrivateKey(cleanedKey));
        } catch (FileNotFoundException e) {
            log.log(Level.SEVERE, "Can't find file in: " + privateKeyPath, e);
        } catch (NoSuchAlgorithmException e) {
            log.log(Level.SEVERE, "Algorithm not found: RSA", e);
        } catch (IOException e) {
            log.log(Level.SEVERE, "Error closing file streams ", e);
        } catch (InvalidKeySpecException e) {
            log.log(Level.SEVERE, "Invalid key specification", e);
        }
        return Optional.empty();
    }
}
