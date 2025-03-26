package sso.vidhi.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakTokenService  {

    private final PublicKey publicKey;

    @Autowired
    public KeycloakTokenService(KeycloakPublicKeyProvider publicKeyProvider) {
        this.publicKey = publicKeyProvider.getPublicKey();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();
            long expirationTime = claims.getExpiration().getTime();
            long currentTime = System.currentTimeMillis();

            return expirationTime >= currentTime;
        } catch (JwtException e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);

            return jws.getBody().get("preferred_username", String.class);
        } catch (JwtException e) {
            return null;
        }
    }

    public List<String> extractRoles(String token) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();

            Object realmAccess = claims.get("realm_access");
            if (realmAccess instanceof Map) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) ((Map<String, Object>) realmAccess).get("roles");
                return roles != null ? roles : Collections.emptyList();
            }

            return Collections.emptyList();
        } catch (JwtException e) {
            return Collections.emptyList();
        }
    }
}
