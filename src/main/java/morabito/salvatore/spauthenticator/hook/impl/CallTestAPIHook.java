package morabito.salvatore.spauthenticator.hook.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import morabito.salvatore.spauthenticator.data.testsignature.SignatureData;
import morabito.salvatore.spauthenticator.data.testsignature.TestAuthenticationResponseData;
import morabito.salvatore.spauthenticator.hook.SignatureHook;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

@RequiredArgsConstructor
@Log
@Component
public class CallTestAPIHook implements SignatureHook {

    @Value("${sp.test.signature.url}")
    private String testSignatureUrl;

    private final RestTemplate testApiRestTemplate;

    @Override
    public void execute(HttpHeaders httpHeaders, String httpMethod, byte[] body) {
        HttpEntity<byte[]> entity = new HttpEntity<>(body, httpHeaders);
        ResponseEntity<TestAuthenticationResponseData> responseEntity = testApiRestTemplate.exchange(testSignatureUrl,
                HttpMethod.valueOf(httpMethod), entity, TestAuthenticationResponseData.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            TestAuthenticationResponseData responseData = responseEntity.getBody();
            log.info("TEST RESPONSE: " + responseData);
            Optional.ofNullable(responseData)
                    .map(TestAuthenticationResponseData::getSignature)
                    .map(SignatureData::getValid)
                    .ifPresentOrElse(valid -> log.info("Reponse is valid: " + valid),
                            () -> log.warning("Authentication FAILED!"));
        }
    }
}
