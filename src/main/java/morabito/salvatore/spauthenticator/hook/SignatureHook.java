package morabito.salvatore.spauthenticator.hook;

import org.springframework.http.HttpHeaders;

public interface SignatureHook {
    void execute(HttpHeaders httpHeaders, String httpMethod, byte[] body);
}
