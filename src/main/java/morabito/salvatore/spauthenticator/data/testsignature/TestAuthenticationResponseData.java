package morabito.salvatore.spauthenticator.data.testsignature;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
@ToString
public class TestAuthenticationResponseData {

    @JsonProperty("authentication_key")
    private TestAuthenticationKeyData authenticationKey;
    private SignatureData signature;
}
