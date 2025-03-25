package afishaBMSTU.auth_lib.security;

import afishaBMSTU.auth_lib.security.exception.IncorrectTokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.Map;

public abstract class BaseJwtService<T> {

    @Value("${security.jwt.secret}")
    private String secret;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public T extractUserInfo(String token) {
        if (token == null || !token.startsWith("Bearer")) {
            throw new IncorrectTokenException("Missing bearer prefix");
        }

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token.substring(7))
                .getBody();


        return objectMapper.convertValue(claims.get("data", Map.class), getDataType());
    }

    protected abstract Class<T> getDataType();

    protected String generateToken(T data) {
        return null;
    }

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }
}
