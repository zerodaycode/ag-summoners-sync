package com.zerodaycode.summonerssync.apigateway.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtValidationFilter extends AbstractGatewayFilterFactory<JwtValidationFilter.Config> {

    private static final Logger log = LoggerFactory.getLogger(JwtValidationFilter.class);

    @Value("${jwt.secret:}")
    private String secretKey;

    @Value("${jwt.devToken:}")
    private String devToken;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    public JwtValidationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = extractJwt(exchange.getRequest().getHeaders());
            log.info("Processing request with JWT token: {}", token);

            if ("dev".equalsIgnoreCase(activeProfile)) {
                // Validate the token in dev mode
                if (!devToken.equals(token)) {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            } else {
                // Production mode: validate JWT with secret
                try {
                    Claims claims = Jwts.parserBuilder()
                        .setSigningKey(secretKey.getBytes())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                    String role = claims.get("role", String.class);
                    log.info("JWT claims extracted. Role: {}", role);

                    if (!config.roles.contains(role)) {
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return exchange.getResponse().setComplete();
                    }
                } catch (SignatureException e) {
                    log.error("Invalid JWT signature", e);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            }
            return chain.filter(exchange);
        };
    }

    private String extractJwt(HttpHeaders headers) {
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        return (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;
    }

    @Setter
    @Getter
    public static class Config {
        private List<String> roles;

    }
}
