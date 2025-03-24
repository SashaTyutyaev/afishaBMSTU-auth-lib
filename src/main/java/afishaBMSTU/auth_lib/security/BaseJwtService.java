package afishaBMSTU.auth_lib.security;

import afishaBMSTU.auth_lib.security.exception.IncorrectTokenException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.List;

public abstract class BaseJwtService<T> {

    @Value("${security.jwt.secret}")
    private String secret;

    protected String extractUserUUID(String token) {
        if (token == null || !token.startsWith("Bearer")) {
            throw new IncorrectTokenException("Missing bearer prefix");
        }

        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token.substring(7))
                .getBody()
                .getSubject();
    }

    protected abstract String generateToken(T data, List<String> roles);

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }
}
