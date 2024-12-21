package com.zerodaycode.summonerssync.apigateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtValidationFilter extends AbstractGatewayFilterFactory<Roles> {

    private static final Logger log = LoggerFactory.getLogger(JwtValidationFilter.class);

    private final JwtUtil jwtUtil;

    @Value("${jwt.devToken:}")
    private String devToken;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    public JwtValidationFilter(JwtUtil jwtUtil) {
        super(Roles.class);
        this.jwtUtil = jwtUtil;
    }

    public GatewayFilter apply(Roles roles) {
        return (exchange, chain) -> {
            final var headers = exchange.getRequest().getHeaders();
            final var token = jwtUtil.extractJwt(headers);
            log.info("Processing request with JWT token: {}", token);

            // Validate the token in dev mode
            if (activeProfile.equals("dev")) {
                if (!devToken.equals(token)) {
                    log.error("Invalid JWT token on 'dev' profile");
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            } else {
                try {
                    jwtUtil.validateToken(token);
                    // TODO: we may take care of this validation seriously,
                    // and consume the published
                } catch (final Exception ex) {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            }

            return chain.filter(exchange);
        };
    }
}
