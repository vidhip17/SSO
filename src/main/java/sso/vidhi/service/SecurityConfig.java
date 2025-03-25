//package sso.vidhi.service;
//
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import sso.vidhi.config.OAuth2TokenSuccessHandler;
//import sso.vidhi.filter.OAuth2TokenFilter;
//
//import java.io.IOException;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .csrf(csrf -> csrf.disable())  // Disable CSRF for simplicity; configure as per your needs
//                .authorizeHttpRequests(authorizeRequests ->
//                        authorizeRequests
//                                .requestMatchers("/login", "/oauth2/authorization/keycloak").permitAll()  // Allow unauthenticated access to login and oauth2 authorization
//                                .anyRequest().authenticated()  // Require authentication for all other requests
//                )
//                .exceptionHandling(exceptionHandling ->
//                        exceptionHandling
//                                .authenticationEntryPoint((request, response, authException) -> {
//                                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                                    response.getWriter().write("Unauthorized access: You need to authenticate.");
//                                })
//                                .accessDeniedHandler((request, response, accessDeniedException) -> {
//                                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//                                    response.getWriter().write("Forbidden access: You do not have the required role or access token.");
//                                })
//                )
//                .oauth2Login(oauth2Login ->
//                        oauth2Login
//                                .loginPage("/login")  // Custom login page if needed, can be omitted if using default login
//                                .successHandler(new OAuth2TokenSuccessHandler())
//                ).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilterBefore(new OAuth2TokenFilter(), UsernamePasswordAuthenticationFilter.class)
//                .logout(logout ->
//                logout
//                        .logoutUrl("/logout")  // Specify logout URL
//                        .logoutSuccessUrl("/login?logout")  // Redirect to login page after logout
//                        .addLogoutHandler((request, response, authentication) -> {
//                            invalidateTokenInKeycloak(request, response);
//                        })
//                        .clearAuthentication(true)  // Clear authentication after logout
//                        .invalidateHttpSession(true)  // Invalidate the HTTP session
//        );;
//
//        return http.build();
//    }
//
//    private void invalidateTokenInKeycloak(HttpServletRequest request, HttpServletResponse response) {
//        String accessToken = extractTokenFromCookie(request, "access_token");
//
//        if (accessToken != null) {
//            String keycloakLogoutUrl = "https://localhost:8080/realms/mytest/protocol/openid-connect/logout";
//            String logoutUrl = keycloakLogoutUrl + "?id_token_hint=" + accessToken + "&post_logout_redirect_uri=" + "http://localhost:8080/login";
//
//            try {
//                response.sendRedirect(logoutUrl);
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//    }
//
//    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
//        if (request.getCookies() != null) {
//            for (Cookie cookie : request.getCookies()) {
//                if (cookieName.equals(cookie.getName())) {
//                    return cookie.getValue();
//                }
//            }
//        }
//        return null;
//    }
//}

package sso.vidhi.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import sso.vidhi.config.OAuth2TokenSuccessHandler;
import sso.vidhi.filter.OAuth2TokenFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Autowired
    private OAuth2TokenSuccessHandler oauth2TokenSuccessHandler;

    @Autowired
    private OAuth2TokenFilter oAuth2TokenFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())  // Disable CSRF for simplicity
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                // Public endpoints
                                .requestMatchers("/login", "/login/oauth2/code/keycloak", "/oauth2/authorization/keycloak", "/css/**", "/js/**", "/images/**").permitAll()
                                // Protected endpoints
                                .anyRequest().authenticated()
                )
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint((request, response, authException) -> {
                                    // Redirect to login page when authentication is required
                                    System.err.println("OAuth2 authentication failed 33333333333: ");
                                    response.sendRedirect("/oauth2/authorization/keycloak");
                                })
                )
                // OAuth2 login configuration
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                //.loginPage("/login")  // Use our custom login page
                                .defaultSuccessUrl("/home", true)  // Added default success URL
                                .successHandler(oauth2TokenSuccessHandler)  // Use a Bean method to create the handler
                                .failureHandler((request, response, exception) -> {  // Better error handling
                                    // Log the exception
                                    System.err.println("OAuth2 authentication failed: " + exception.getMessage());
                                    exception.printStackTrace();
                                    // Redirect to login with error
                                    response.sendRedirect("/login?error=" + URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8));
                                })
                                .userInfoEndpoint(userInfo -> userInfo  // Add this section for proper user info handling
                                        .userService(this.oauth2UserService())
                                )
//                                .successHandler(new OAuth2TokenSuccessHandler())
//                                .failureUrl("/login?error")// Handle success and set cookies
                )
                // Session management
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Token filter to validate tokens in cookies
                .addFilterBefore(oAuth2TokenFilter, UsernamePasswordAuthenticationFilter.class)
                // Logout configuration
                .logout(logout ->
                        logout
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                                .addLogoutHandler((request, response, authentication) -> {
                                    // Clear cookies

//                                    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
//                                    String idToken = (String) oauthToken.getPrincipal()
//                                            .getAttributes()
//                                            .get("id_token");
                                    String idToken = extractTokenFromCookie(request, "id_token");
                                    clearCookie(response, "access_token");
                                    clearCookie(response, "refresh_token");

                                    // Redirect to Keycloak logout endpoint
//                                    String accessToken = extractTokenFromCookie(request, "access_token");
//                                    if (accessToken != null) {
//                                        String keycloakLogoutUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/logout";
//                                        String logoutUrl = keycloakLogoutUrl +
//                                                "?id_token_hint=" + idToken +
//                                                "&post_logout_redirect_uri=http://localhost:8080/login";
//
//                                        try {
//                                            response.sendRedirect(logoutUrl);
//                                        } catch (IOException e) {
//                                            e.printStackTrace();
//                                        }
//                                    }

                                    if (idToken != null) {
                                        String keycloakLogoutUrl = keycloakAuthServerUrl
                                                + "/realms/" + keycloakRealm
                                                + "/protocol/openid-connect/logout";

                                        String encodedIdToken = URLEncoder.encode(idToken, StandardCharsets.UTF_8);
                                        String logoutUrl = keycloakLogoutUrl +
                                                "?id_token_hint=" + encodedIdToken +
                                                "&post_logout_redirect_uri=http://localhost:9090/oauth2/authorization/keycloak";

                                        try {
                                            response.sendRedirect(logoutUrl);
                                        } catch (IOException e) {
                                            // Log error instead of printing stack trace
                                            System.err.println("Logout redirection failed: " + e.getMessage());
                                        }
                                    }
                                })
                                .clearAuthentication(true)
                                .invalidateHttpSession(true)
                                .logoutSuccessUrl("/login?logout")
                );

        return http.build();
    }



    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return userRequest -> {
            OAuth2User oauth2User = delegate.loadUser(userRequest);

            // Extract client registration
            String registrationId = userRequest.getClientRegistration().getRegistrationId();

            // For Keycloak, set the name attribute
            if ("keycloak".equals(registrationId)) {
                Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());
                return new DefaultOAuth2User(
                        oauth2User.getAuthorities(),
                        attributes,
                        "preferred_username"  // This is typically the username attribute in Keycloak
                );
            }

            return oauth2User;
        };
    }

}
