package morabito.salvatore.spauthenticator.data.testsignature;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
@ToString
public class SignatureData {

    @JsonProperty("key_id")
    private String keyId;
    private String algorithm;
    private List<String> headers;
    private Boolean valid;
}
