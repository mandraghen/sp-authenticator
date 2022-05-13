package morabito.salvatore.spauthenticator.data;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.http.HttpHeaders;

@Getter
@Setter
@ToString
public class AuthenticationResponseData {
    private HttpHeaders httpHeaders;
}
