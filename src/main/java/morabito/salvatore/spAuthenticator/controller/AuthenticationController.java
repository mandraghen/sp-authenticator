package morabito.salvatore.spAuthenticator.controller;


import lombok.extern.java.Log;
import morabito.salvatore.spAuthenticator.service.DigitalSignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Log
@RestController
@RequestMapping("/authenticate")
public class AuthenticationController {

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @GetMapping
    public HttpHeaders authenticateGet(@RequestParam(value = "targetUrl") String targetUrl,
                                       @RequestHeader HttpHeaders headers, @RequestBody(required = false) byte[] body) {
        return createHeaders(targetUrl, HttpMethod.GET, headers, body);
    }

    @PostMapping
    public void authenticatePost(@RequestParam(value = "targetUrl") String targetUrl) {

    }

    @PutMapping
    public void authenticatePut(@RequestParam(value = "targetUrl") String targetUrl) {

    }

    @DeleteMapping
    public void authenticateDelete(@RequestParam(value = "targetUrl") String targetUrl) {

    }

    private HttpHeaders createHeaders(String destinationUrl, HttpMethod httpMethod,
                                      HttpHeaders requestHeaders, byte[] body) {
        HttpHeaders signHeaders =
                digitalSignatureService.createSignHeaders(destinationUrl, httpMethod, requestHeaders, body);
        log.info("Created headers: " + signHeaders.toString());

        return signHeaders;
    }
}
