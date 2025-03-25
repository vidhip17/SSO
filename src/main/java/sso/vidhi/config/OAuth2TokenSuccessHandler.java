package sso.vidhi.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import sso.vidhi.utils.OAuth2Utils;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;

@Component
public class OAuth2TokenSuccessHandler implements AuthenticationSuccessHandler {
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        if (authentication instanceof OAuth2AuthenticationToken) {
//            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
//            // Handle OAuth2 authentication success, store tokens, etc.
//            // For example, you can store the access token in a cookie:
//            System.out.println("Authentication successful if!");
//            String accessToken = oauthToken.getPrincipal().getAttributes().get("access_token").toString();
//            response.addCookie(new Cookie("access_token", accessToken));  // Store token in cookie or session as required
//        }
//        OAuth2LoginAuthenticationToken authToken = (OAuth2LoginAuthenticationToken) authentication;
//        OAuth2User user = authToken.getPrincipal();
//
//        System.out.println("Authentication successful!");
//        System.out.println("User authenticated: " + authentication.getName());
//
//        // You can also log details
//        Logger.getLogger(OAuth2TokenSuccessHandler.class.getName())
//                .info("Authentication successful for: " + authentication.getName());
//
//        String accessToken = (String) user.getAttributes().get("access_token");
//        String refreshToken = (String) user.getAttributes().get("refresh_token");
//        String idToken = (String) user.getAttributes().get("id_token");
//
//        System.out.println("token;ljkbjhvvuy"+accessToken);
//
//        // Store tokens in HTTP-only cookies
//        storeTokenInCookie(response, "access_token", accessToken);
//        storeTokenInCookie(response, "refresh_token", refreshToken);
//        storeTokenInCookie(response, "id_token", idToken);
//
//        // Redirect after successful authentication
//        response.sendRedirect("/home");
//    }

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.redirect-uri}")
    private String redirectUri;

//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
//        if (authentication instanceof OAuth2AuthenticationToken) {
//            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
//
//            // Get the authorization code from the authentication
//            //String authorizationCode = oauthToken.getAuthorizationCode();
//            Map<String, Object> details = (Map<String, Object>) oauthToken.getDetails();
//
//            // Retrieve the authorization code from the details
//            String authorizationCode = (String) details.get("code");
//            if (authorizationCode != null) {
//                // Call exchangeCodeForToken to exchange the authorization code for an access token
//                OAuth2AccessTokenResponse tokenResponse = OAuth2Utils.exchangeCodeForToken(
//                        authorizationCode,
//                        redirectUri,
//                        clientId,
//                        null
//                );
//
//                // Handle the access token, e.g., save it in a cookie or session
//                String accessToken = tokenResponse.getAccessToken().getTokenValue();
//                response.addCookie(new Cookie("access_token", accessToken)); // Store token in cookie or session
//            }
//        }
//
//        // Redirect to a default page after successful login
//        response.sendRedirect("/home");
//    }

    private final OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    public OAuth2TokenSuccessHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }
//
//    public OAuth2TokenSuccessHandler() {
//    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

            // Debug: Print user attributes
            OAuth2User oauth2User = oauthToken.getPrincipal();
            System.out.println("User attributes from Keycloak:");
            oauth2User.getAttributes().forEach((key, value) -> {
                System.out.println(key + " -> " + value);
            });

            String idToken = null;
            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                idToken = oidcUser.getIdToken().getTokenValue();
            }

            String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();

            // Get principal name
            String principalName = authentication.getName();

            // Load the OAuth2 authorized client containing the access token
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    clientRegistrationId, principalName);

            if (client != null && client.getAccessToken() != null) {
                // Get access token
                String accessToken = client.getAccessToken().getTokenValue();

                storeTokenInCookie(response, "access_token", accessToken);

                // If there's a refresh token, save it too
                if (client.getRefreshToken() != null) {
                    String refreshToken = client.getRefreshToken().getTokenValue();
//                    Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
//                    refreshTokenCookie.setHttpOnly(true);
//                    refreshTokenCookie.setPath("/");
//                    // For production use:
//                    // refreshTokenCookie.setSecure(true);
//                    response.addCookie(refreshTokenCookie);
                    storeTokenInCookie(response, "refresh_token", refreshToken);
                }

                if (idToken != null) {

                    storeTokenInCookie(response, "id_token", idToken);
                }

                System.out.println("Successfully set access token cookie for user: " + principalName);
            } else {
                System.err.println("Failed to get access token for user: " + principalName);
            }
        }

        // Redirect to home page
        response.sendRedirect("/home");
    }

    private void storeTokenInCookie(HttpServletResponse response, String cookieName, String token) {
        if (token != null) {
            Cookie cookie = new Cookie(cookieName, token);
            cookie.setHttpOnly(true);  // Prevent JavaScript from accessing the cookie
            cookie.setSecure(true);  // Ensure cookie is only sent over HTTPS
            cookie.setPath("/");  // Accessible throughout the application
            cookie.setMaxAge(3600);  // Set expiration time to 1 hour (in seconds)
            response.addCookie(cookie);  // Add the cookie to the response

            response.addHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; Path=" + cookie.getPath()
                    + "; Max-Age=" + cookie.getMaxAge() + "; HttpOnly; Secure; SameSite=None");
        }
    }
}
