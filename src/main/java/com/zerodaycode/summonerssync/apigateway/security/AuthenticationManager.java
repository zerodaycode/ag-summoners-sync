package com.zerodaycode.summonerssync.apigateway.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private static final String DEFAULT_ROLE = "ROLE_USER";
    private final JwtUtil jwtUtil;

    public AuthenticationManager(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        return Mono.just(authentication.getCredentials().toString())
            .flatMap(this::verifyToken);
//            .flatMap(this::getAuthentication);
    }

//    private Mono<Authentication> getAuthentication(AuthenticationTokenData appUser) {
//        return Mono.just(
//            new UsernamePasswordAuthenticationToken(getGrantedAuthorities(), appUser,
//                null)
//        );
//    }

    private Collection<SimpleGrantedAuthority> getGrantedAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private Mono<Authentication> verifyToken(String token) {
        return jwtUtil.validateToken(token)
            .filter(decodedJWT -> decodedJWT.getAudience() != null && !decodedJWT.getAudience().isEmpty())
            .flatMap(tokenData -> getUser(tokenData, token));
    }

    private Mono<? extends Authentication> getUser(DecodedJWT tokenData, String token) {
        return Mono.just(new UsernamePasswordAuthenticationToken(token, null, getGrantedAuthorities()));
    }

//    private Mono<AuthenticationTokenData> verifyToken(String token) {
//
//        return tokenService.verifyToken(token)
//            .filter(decodedJWT -> decodedJWT.getAudience() != null && !decodedJWT.getAudience().isEmpty())
//            .flatMap(tokenData -> getAppUser(tokenData, token));
//    }

//    private Mono<AuthenticationTokenData> getAppUser(DecodedJWT decodedJWT, String token) {
//        return Mono.just(AuthenticationTokenData.builder()
//            .userAudience(decodedJWT.getAudience().get(0))
//            .userId(decodedJWT.getClaim(TOKEN_CLAIM_USER).asString())
//            .deviceId(decodedJWT.getClaim(TOKEN_CLAIM_DEVICE).asString())
//            .token(token)
//            .build()
//        );
//    }
}
