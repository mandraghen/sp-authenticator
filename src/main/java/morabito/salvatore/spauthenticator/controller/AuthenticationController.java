package morabito.salvatore.spauthenticator.controller;


import lombok.extern.java.Log;
import morabito.salvatore.spauthenticator.data.AuthenticationResponseData;
import morabito.salvatore.spauthenticator.service.DigitalSignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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

//    @GetMapping
//    public HttpHeaders authenticateGet(@RequestParam(value = "targetUrl") String targetUrl,
//                                       @RequestHeader HttpHeaders headers, @RequestBody(required = false) byte[] body) {
//        return createHeaders(targetUrl, HttpMethod.GET, headers, body);
//    }

    @PostMapping(value = "{httpMethod}", produces = MediaType.APPLICATION_JSON_VALUE)
    public AuthenticationResponseData authenticatePost(@RequestParam(value = "targetUrl") String targetUrl,
                                                       @RequestHeader HttpHeaders headers, @PathVariable String httpMethod,
                                                       @RequestBody(required = false) byte[] body) {
        return createHeaders(targetUrl, httpMethod, headers, body);
    }
//
//    @PutMapping
//    public void authenticatePut(@RequestParam(value = "targetUrl") String targetUrl) {
//
//    }
//
//    @DeleteMapping
//    public void authenticateDelete(@RequestParam(value = "targetUrl") String targetUrl) {
//
//    }

    private AuthenticationResponseData createHeaders(String destinationUrl, String httpMethod,
                                                     HttpHeaders requestHeaders, byte[] body) {
        HttpHeaders signHeaders =
                digitalSignatureService.createSignHeaders(destinationUrl, httpMethod, requestHeaders, body);
        log.info("Created headers: " + signHeaders.toString());

        var response = new AuthenticationResponseData();
        response.setHttpHeaders(signHeaders);

        return response;
    }
}
