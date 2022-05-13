package morabito.salvatore.spauthenticator.service;

import org.springframework.http.HttpHeaders;

public interface DigitalSignatureService {
    HttpHeaders createSignHeaders(String destinationUrl, String httpMethod,
                                  HttpHeaders requestHeaders, byte[] body);
}
