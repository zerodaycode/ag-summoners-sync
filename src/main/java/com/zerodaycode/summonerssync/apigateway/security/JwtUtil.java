package com.zerodaycode.summonerssync.apigateway.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtUtil {
    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret:}")
    private String secretKey;
//
//    public HttpStatus validateToken(String token, Roles roles) {
//        try {
//            Claims claims = Jwts.parserBuilder()
//                .setSigningKey(secretKey.getBytes())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//            String role = claims.get("role", String.class);
//            log.info("JWT claims extracted. Role: {}", role);
//
//            if (!roles.getRoles().contains(role)) {
//                return HttpStatus.FORBIDDEN;
//            }
//        } catch (SignatureException e) {
//            return HttpStatus.UNAUTHORIZED;
//        }
//
//        return HttpStatus.OK;
//    }
//
    public String extractJwt(final HttpHeaders headers) {
        final String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        return (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;
    }
//    @SneakyThrows
//public boolean validateToken(final String token)
////    throws JwtTokenMalformedException, JwtTokenMissingException
//{
//    try {
//        Jwts.parserBuilder()
//            .setSigningKey(secretKey.getBytes())
//            .build()
//            .parseClaimsJws(token);
//         // TODO: enum with custom auth statuses?
//        return true;
//    } catch (SignatureException ex) {
//        throw new RuntimeException("Invalid JWT signature");
//    }
    public Mono<DecodedJWT> validateToken(String token) {
    try {
        return Mono.just(JWT
//                    .create()
                    .require(Algorithm.HMAC256(secretKey))
                    .withAudience(token)
//                .require(algorithm)
//                .withKeyId(secretKey)
//                .withIssuer("zero-day-code-issuer")
                .build())
            .map(verifier -> {
                var r = verifier.verify(token);
                log.info("JWT verified with {}", r.getSignature());
                return r;
            });
    } catch (SignatureVerificationException
             | AlgorithmMismatchException
             | TokenExpiredException
             | InvalidClaimException e) {
        return Mono.error(() -> new RuntimeException("Token Verification Failed - {}", e));
    }
}
//    return false;
//    } catch (MalformedJwtException ex) {
//        throw new JwtTokenMalformedException("Invalid JWT token");
//    } catch (ExpiredJwtException ex) {
//        throw new JwtTokenMalformedException("Expired JWT token");
//    } catch (UnsupportedJwtException ex) {
//        throw new JwtTokenMalformedException("Unsupported JWT token");
//    } catch (IllegalArgumentException ex) {
//        throw new JwtTokenMissingException("JWT claims string is empty.");
//    }
}
//    public Mono<DecodedJWT> verifyToken(String token) {
//        try {
//            return Mono.just(JWT.require(algorithm)
//                    .withIssuer(TOKEN_ISSUER)
//                    .build())
//                .map(verifier -> verifier.verify(token));
//        } catch (Exception e) {
//            return Mono.error(() -> new RuntimeException("Token Verification Failed - {}", e));
//        }
//    }

