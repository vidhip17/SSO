//package sso.vidhi.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
//import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
//import org.springframework.security.oauth2.client.*;
//
//@Configuration
//public class OAuth2Config {
//
//    @Bean
//    public OAuth2AuthorizedClientService oAuth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository,
//                                                                       OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
//        return null;
//
//    }
//
//    @Bean
//    public OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(OAuth2AuthorizedClientManager authorizedClientManager) {
//        return new HttpSessionOAuth2AuthorizedClientRepository();
//    }
//}
