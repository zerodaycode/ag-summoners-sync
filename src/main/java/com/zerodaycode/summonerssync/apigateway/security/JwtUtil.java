package com.zerodaycode.summonerssync.apigateway.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtUtil {
    // TODO: ctes below are intended to be hold in the Rust FFI lib, and shared between the Java
    // artifacts to create the token with the same lib
    public static final String TOKEN_ISSUER = "https://summoners-sync.io";
    public static final String TOKEN_SCOPE = "scope";
    public static final String TOKEN_SUBJECT = "client-app";
    public static final String TOKEN_CLAIM_USER = "user-id";
    public static final String TOKEN_CLAIM_DEVICE = "device-id";
    public static final String[] TOKEN_SCOPE_ARRAY = new String[]{"authentication", "authorization"};
    public static final String[] TOKEN_AUDIENCES_ARRAY = new String[]{"public-api", "login", "register"};

    @Value("${jwt.secret:}")
    private String secretKey;

    public String extractJwt(final HttpHeaders headers) {
        final String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        return (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : "";
    }

    public Mono<DecodedJWT> validateToken(String token) {
        final var algorithm = Algorithm.HMAC256(secretKey);
        final var verifier = Mono.just(JWT
            .require(algorithm)
            .build());
        try {
            return verifier
                .map(v -> v.verify(token));
        } catch (SignatureVerificationException
                 | AlgorithmMismatchException
                 | TokenExpiredException
                 | InvalidClaimException e) {
            return Mono.error(() -> new RuntimeException(/*TODO: review this except*/"Token Verification Failed - {}", e));
        }
    }
}

