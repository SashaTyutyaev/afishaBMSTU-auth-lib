package afishaBMSTU.auth_lib.security.internal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Service
public class InternalTokenService {

    @Value("${security.internal.token}")
    private String internalToken;

    protected boolean validateInternalToken(String token) {
        return new String(Base64.getDecoder().decode(internalToken))
                .trim().equals(token) && !token.isEmpty();
    }

    protected String getServiceNameFromToken(String token) {
        return token;
    }

    protected List<String> getRolesFromToken(String token) {
        return validateInternalToken(token)
                ? Collections.singletonList("ROLE_INTERNAL_SERVICE")
                : Collections.emptyList();
    }
}
