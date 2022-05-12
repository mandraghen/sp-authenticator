package morabito.salvatore.spAuthenticator.service;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

public interface DigitalSignatureService {
    HttpHeaders createSignHeaders(String destinationUrl, HttpMethod httpMethod,
                                  HttpHeaders requestHeaders, byte[] body);
}
