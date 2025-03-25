package sso.vidhi.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import sso.vidhi.utils.OAuth2Utils;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

@RestController
@RequestMapping("")
public class LoginController {
    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String keycloakClientId;

    @Autowired
    private OAuth2Utils oAuth2Utils;

    private final String tokenEndpoint = "http://localhost:8080/realms/mytest/protocol/openid-connect/token";
    private final String clientId = "Test";
    private final String redirectUri = "http://localhost:9090/login/oauth2/code/keycloak";

//    @GetMapping("/login")
//    public ResponseEntity<String> login() {
//        // Redirect to Keycloak login page
//        return ResponseEntity.status(302)
//                .header("Location", "http://localhost:9090")
//                .build();
//    }
    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error) {
        if (error != null) {
            // Log the error and show an error message to the user
            System.out.println("OAuth2 login error: " + error);
        }
        return "login";  // Return the login page
    }

    @GetMapping("/home")
    public String home()  {

        return "home";  // Return the login page
    }


    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        // Construct the URL to get the token
        String tokenUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";

        // Create the parameters for the token request (password grant)
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", keycloakClientId);
        body.add("username", username);
        body.add("password", password);
        body.add("grant_type", "password");
        body.add("scope", "openid");

        // Set up the headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");

        // Set up the rest template and make the POST request to Keycloak
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = null; // Declare response here to use it later

        try {
            // Making the POST request to Keycloak to get the token
            response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, String.class);
        } catch (Exception e) {
            // If an error occurs, print the cause and return an error message
            Throwable cause = e.getCause();
            if (cause != null) {
                cause.printStackTrace(); // Print the underlying cause for debugging
            }
            // Return unauthorized status with a message indicating the failure
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed: " + e.getMessage());
        }

        // Check if the response is successful and return the access token or an error
        if (response != null && response.getStatusCode() == HttpStatus.OK) {
            // Successfully received the token, return it
            return ResponseEntity.ok("Login Successful: " + response.getBody());
        } else {
            // If response is null or not OK, return the error response
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Login failed: Invalid response or token acquisition failed.");
        }
    }

    @GetMapping("/login/oauth2/code/keycloak")
    public String login(@RequestParam Map<String, String> params, HttpSession session) {
        // Log session attributes
        System.out.println("Session Attributes: " + session.getAttributeNames());
        return "redirect:/home"; // Or wherever you want to redirect after login
    }

//    @GetMapping("/login/oauth2/code/keycloak")
//    public String handleOAuth2Login(@RequestParam("code") String authorizationCode, OAuth2AuthenticationToken oauthToken) {
//        // The OAuth2AuthenticationToken contains the details as an Object
//        Map<String, Object> details = (Map<String, Object>) oauthToken.getDetails();
//
//        // Retrieve the authorization code from the details map (if present)
//        if (details != null && details.containsKey("code")) {
//            String code = (String) details.get("code");
//            System.out.println("Authorization Code: " + code);
//        } else {
//            System.out.println("Authorization code not found in details.");
//        }
//
//        // Exchange the authorization code for an access token (for example, by calling the token endpoint)
//        OAuth2AccessTokenResponse tokenResponse = exchangeAuthorizationCodeForToken(authorizationCode);
//
//        // Do something with the token response (e.g., save tokens, set cookies, etc.)
//
//        return "redirect:/home";  // Redirect to a secured page after login
//    }

    private OAuth2AccessTokenResponse exchangeAuthorizationCodeForToken(String authorizationCode) {
        RestTemplate restTemplate = new RestTemplate();

        // Prepare the request body with authorization code, client ID, client secret, etc.
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", authorizationCode);
        body.add("redirect_uri", redirectUri);
        body.add("client_id", clientId);

        // Make the POST request to exchange the authorization code for an access token
        ResponseEntity<OAuth2AccessTokenResponse> responseEntity = restTemplate.postForEntity(tokenEndpoint, body, OAuth2AccessTokenResponse.class);

        return responseEntity.getBody();  // Return the token response
    }


    // Endpoint for logout from Keycloak
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        String accessToken = authHeader.replace("Bearer ", "");

        // Construct Keycloak logout URL
        String logoutUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/logout" +
                "?id_token_hint=" + accessToken + "&post_logout_redirect_uri=http://localhost:8080/login";

        // Redirect to Keycloak's logout URL
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", logoutUrl).build();
    }

}
