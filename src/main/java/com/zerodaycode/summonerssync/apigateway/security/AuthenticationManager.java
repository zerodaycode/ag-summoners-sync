package com.zerodaycode.summonerssync.apigateway.security;

import com.auth0.jwt.interfaces.DecodedJWT;
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
    private final JwtUtil jwtUtil;

    public AuthenticationManager(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        return Mono.just(authentication.getCredentials().toString())
            .flatMap(this::verifyToken); // we should split this taking the commented code for now
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
//            .filter(decodedJWT -> decodedJWT.getAudience() != null && !decodedJWT.getAudience().isEmpty())
            .flatMap(tokenData -> getUser(tokenData, token));
    }

    private Mono<? extends Authentication> getUser(DecodedJWT tokenData, String token) {
        var c = new SimpleGrantedAuthority(tokenData.getClaim("role").toString());
        var a = new UsernamePasswordAuthenticationToken(token, null, List.of(c));
        return Mono.just(a);
    }
}
