package com.zerodaycode.summonerssync.apigateway.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
//
//@Configuration
//@EnableWebFluxSecurity
//public class SecurityConfig {
//
//    @Bean
//    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
//        System.out.println("springWebFilterChain");
//        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
//
//        http.authorizeExchange(authorize -> authorize
//            .pathMatchers("/auth/**").permitAll()
//            .anyExchange()
//            .authenticated()
//        );
//
////        http.exceptionHandling(exception -> exception
////            .accessDeniedHandler((exchange, ex) -> {
////                final ServerHttpResponse response = exchange.getResponse();
////                response.setStatusCode(HttpStatus.FORBIDDEN);
////                return setAuthExceptionMessage(response, "Access denied: ", ex);
////            })
////            .authenticationEntryPoint((exchange, ex) -> {
////                final ServerHttpResponse response = exchange.getResponse();
////                response.setStatusCode(HttpStatus.UNAUTHORIZED);
////                return setAuthExceptionMessage(response, "Unauthorized Access: ", ex);
////            })
////        );
//        return http.build();
//    }
//
//    private Mono<Void> setAuthExceptionMessage(ServerHttpResponse res, final String message, final Exception ex) {
//        final String exReason = ex.getCause().getMessage().split(":")[1];
//        return res.writeWith(Mono.just(
//            res.bufferFactory().wrap((message + exReason).getBytes())
//        ));
//    }
//}

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(authorize -> authorize
                .pathMatchers("/auth/**").permitAll()
                .anyExchange().authenticated()
            )
            .httpBasic(); // TODO: pending to be removed
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
        return http.build();
    }
}
