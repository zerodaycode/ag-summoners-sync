package com.zerodaycode.summonerssync.apigateway.config;


import com.zerodaycode.summonerssync.apigateway.auth.JwtValidationFilter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.SecurityWebFilterChain;



@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final Logger log = LoggerFactory.getLogger(this.getClass());

//    private final JwtValidationFilter jwtValidationFilter;

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        log.info("Received request: {}", http);
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.authorizeExchange(authorize -> authorize
                .pathMatchers("/auth/**")
                    .permitAll()
                .anyExchange()
                .authenticated()
            );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
        return http.build();
    }
}
