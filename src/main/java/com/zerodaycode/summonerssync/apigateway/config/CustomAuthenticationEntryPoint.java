package com.zerodaycode.summonerssync.apigateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Configuration
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException exception) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);

        // Custom JSON error message
        ErrorResponse errorResponse = new ErrorResponse(
            HttpStatus.UNAUTHORIZED.value(),
            "Unauthorized Access",
            LocalDateTime.now()
        );

        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorResponse.toJson().getBytes())));
    }
}

class ErrorResponse {
    private final int status;
    private final String message;
    private final LocalDateTime timestamp;

    public ErrorResponse(int status, String message, LocalDateTime timestamp) {
        this.status = status;
        this.message = message;
        this.timestamp = timestamp;
    }

    public String toJson() {
        return String.format("{\"status\":%d,\"message\":\"%s\",\"timestamp\":\"%s\"}", status, message, timestamp);
    }
}
