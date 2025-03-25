package afishaBMSTU.auth_lib.security.internal;

import afishaBMSTU.auth_lib.security.BaseAuthTokenFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.List;

@RequiredArgsConstructor
public class InternalTokenFilter extends BaseAuthTokenFilter<String> {

    private final InternalTokenService internalTokenService;

    @Override
    protected boolean validateJwtToken(String token) {
        return internalTokenService.validateInternalToken(token);
    }

    @Override
    protected List<String> parseRoles(String token) {
        return internalTokenService.getRolesFromToken(token);
    }

    @Override
    protected String retrieveUserInfo(String token) {
        return internalTokenService.getServiceNameFromToken(token);
    }

    @Override
    protected String parseJwt(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }
}
