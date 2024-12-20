package com.zerodaycode.summonerssync.apigateway.config;


import com.zerodaycode.summonerssync.apigateway.security.AuthenticationManager;
import com.zerodaycode.summonerssync.apigateway.security.SecurityContextRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;



@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {
    private final Logger log = LoggerFactory.getLogger(this.getClass());

//    private final JwtValidationFilter jwtValidationFilter;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public SecurityConfig(AuthenticationManager authenticationManager,
                          SecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        log.info("Received request: {}", http);
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.authenticationManager(authenticationManager);
        http.securityContextRepository(securityContextRepository);
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
