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
public class AuthenticationKeyData {

    @JsonProperty("access_key")
    private String accessKey;
    @JsonProperty("customer_uid")
    private String customerUid;
    @JsonProperty("key_type")
    private String keyType;
    @JsonProperty("auth_type")
    private String authType;
    private String role;
    private Boolean enable;
}
