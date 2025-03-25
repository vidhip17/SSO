package sso.vidhi.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import sso.vidhi.service.KeycloakTokenService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class OAuth2TokenFilter extends OncePerRequestFilter {

    private final KeycloakTokenService tokenService;

    public OAuth2TokenFilter(KeycloakTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = extractTokenFromCookie(request, "access_token");

        if (accessToken != null) {
            Authentication authentication = getAuthenticationFromToken(accessToken);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication); // Set authentication
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();  // Return the token from the cookie
                }
            }
        }
        return null;
    }

    private Authentication getAuthenticationFromToken(String token) {
//        if (token != null && !token.isEmpty()) {
//            return new UsernamePasswordAuthenticationToken("user", null, null); // Fake authentication for demo
//        }
//        return null;

        try {
            // Validate the token first
            if (tokenService.validateToken(token)) {
                // Extract user details from the token
                String username = tokenService.extractUsername(token);
                List<String> roles = tokenService.extractRoles(token);
                System.err.println("inside filter"+username);
                System.err.println("inside filter roles"+roles);

                // Convert roles to GrantedAuthorities
                List<GrantedAuthority> authorities = new ArrayList<>();
                for (String role : roles) {
                    authorities.add(new SimpleGrantedAuthority(role));
                }

                // Create a UserDetails object
                User userDetails = new User(username, "", authorities);

                // Create and return an Authentication object
                return new UsernamePasswordAuthenticationToken(userDetails, token, authorities);
            }
        } catch (Exception e) {
            // Log the error or handle token validation failures
            logger.error("Token validation failed", e);
        }
        return null;
    }
}
