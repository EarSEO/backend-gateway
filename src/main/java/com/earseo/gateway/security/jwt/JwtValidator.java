package com.earseo.gateway.security.jwt;

import com.earseo.gateway.common.exception.AuthError;
import com.earseo.gateway.common.exception.BaseException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtValidator {

    @Value("${jwt.access_secret}")
    private String accessSecret;

    private SecretKey jwtSecretKey;

    @PostConstruct
    public void init() {
        jwtSecretKey = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public Claims validateToken(String token) {
        try {
            return Jwts.parser().verifyWith(jwtSecretKey).build().parseSignedClaims(token).getPayload();
        } catch (SecurityException | MalformedJwtException e) {
            throw new BaseException(AuthError.INVALID_TOKEN);
        } catch (ExpiredJwtException e) {
            throw new BaseException(AuthError.EXPIRED_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw new BaseException(AuthError.UNSUPPORTED_JWT);
        }
    }
}
