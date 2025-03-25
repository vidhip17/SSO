package sso.vidhi.service;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.gson.JsonObject;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

@Component
public class KeycloakPublicKeyProvider {
    private final String keycloakRealmUrl;
    private PublicKey publicKey;

    @Autowired
    public KeycloakPublicKeyProvider(@Value("${keycloak.realm-url}") String keycloakRealmUrl) {
        this.keycloakRealmUrl = keycloakRealmUrl;
        this.publicKey = loadPublicKey();
    }

    private PublicKey loadPublicKey() {
        try {
            URL url = new URL(keycloakRealmUrl + "/protocol/openid-connect/certs");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jwks = objectMapper.readTree(conn.getInputStream());

            // Get the first key's X.509 certificate
            JsonNode keys = jwks.get("keys");
            JsonNode firstKey = keys.get(0);
            String publicKeyString = firstKey.get("x5c").get(0).asText();

            // Convert the X.509 certificate to a PublicKey
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = certFactory.generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(publicKeyString))
            );

            return cert.getPublicKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load Keycloak public key", e);
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
