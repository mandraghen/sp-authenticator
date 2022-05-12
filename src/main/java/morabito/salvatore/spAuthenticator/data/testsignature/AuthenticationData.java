package morabito.salvatore.spAuthenticator.data.testsignature;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
@ToString
public class AuthenticationData {

    @JsonProperty("authentication_key")
    private AuthenticationKeyData authenticationKey;
    private SignatureData signature;
}
