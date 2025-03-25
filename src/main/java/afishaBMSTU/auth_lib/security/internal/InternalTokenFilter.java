package afishaBMSTU.auth_lib.security.internal;

import afishaBMSTU.auth_lib.security.BaseAuthTokenFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@RequiredArgsConstructor
@Slf4j
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

    @Override
    protected boolean shouldSkipFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        log.info("Skipping internal token filter");
        return !requestURI.contains("/api/internal/");
    }
}
