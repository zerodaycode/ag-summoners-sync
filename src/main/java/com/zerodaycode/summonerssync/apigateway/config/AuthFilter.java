//package com.zerodaycode.summonerssync.apigateway.config;
//
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.GatewayFilterChain;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//@Configuration
//public class AuthFilter implements GatewayFilter {
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//        ServerHttpRequest request = exchange.getRequest();
////        if (routerValidator.isSecured.test(request)) {
////            if (this.isAuthMissing(request))
////                return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);
////            final String token = this.getAuthHeader(request);
////            if (jwtUtil.isInvalid(token))
////                return this.onError(exchange, "Authorization header is invalid", HttpStatus.UNAUTHORIZED);
////            this.populateRequestWithHeaders(exchange, token);
////        }
//        return chain.filter(exchange);
//    }
//    /*PRIVATE*/
//    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
//        ServerHttpResponse response = exchange.getResponse();
//        response.setStatusCode(httpStatus);
//        return response.setComplete();
//    }
//    private String getAuthHeader(ServerHttpRequest request) {
//        return request.getHeaders().getOrEmpty("Authorization").getFirst();
//    }
//    private boolean isAuthMissing(ServerHttpRequest request) {
//        return !request.getHeaders().containsKey("Authorization");
//    }
//    private void populateRequestWithHeaders(ServerWebExchange exchange, String token) {
//        Claims claims = jwtUtil.getAllClaimsFromToken(token);
//        exchange.getRequest().mutate()
//            .header("id", String.valueOf(claims.get("id")))
//            .header("role", String.valueOf(claims.get("role")))
//            .build();
//    }
//}
