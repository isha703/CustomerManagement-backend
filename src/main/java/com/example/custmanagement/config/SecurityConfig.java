package com.example.custmanagement.config;

import com.example.custmanagement.security.UserDetailsServiceImpl;
import com.example.custmanagement.security.HttpCookieOAuth2AuthorizationRequestRepository;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;

import com.example.custmanagement.security.CustomAuthenticationSuccessHandler;
import org.springframework.context.annotation.Lazy;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${app.cors.allowed-origins:http://localhost:8081}")
    private String allowedOrigins;



    @Value("${JWT_SECRET:}")
    private String jwtSecret;




    @org.springframework.beans.factory.annotation.Autowired
    @org.springframework.context.annotation.Lazy
    private CustomAuthenticationSuccessHandler successHandler;

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public static HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsServiceImpl userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, com.example.custmanagement.security.JwtCookieAuthenticationFilter jwtCookieFilter) throws Exception {
        http
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                List<String> origins = Arrays.stream(allowedOrigins.split(","))
                        .map(String::trim)
                        .toList();
                config.setAllowCredentials(true);
                config.setAllowedOrigins(origins);
                config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
                config.setAllowedHeaders(List.of("*"));
                config.setMaxAge(3600L);
                return config;
            }))
            .csrf(csrf -> csrf.disable()) // Disable CSRF for JWT / SPA
            .authorizeHttpRequests(auth -> auth
                // allow preflight for everything
                .requestMatchers(HttpMethod.OPTIONS, "**").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/error", "/error/**").permitAll()
                .requestMatchers("/auth/**", "/oauth2/**").permitAll()
                .requestMatchers("/health/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/.well-known/jwks.json").permitAll()
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                // For API requests, return 401 instead of redirecting to login
                .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), new AntPathRequestMatcher("/api/**"))
            )
            .oauth2Login(oauth -> oauth
                //    .authorizationEndpoint(endpoint -> endpoint.authorizationRequestRepository(authorizationRequestRepository()))
                    .successHandler(successHandler)
            )
            // Session management: create sessions when required (OAuth handshake) and set timeout via server.servlet.session.timeout

            .logout(logout -> logout
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "access_token", "refresh_token")
            );

        // concurrent session control: allow only one active session per user (uses sessionRegistry bean)


        // Insert cookie-based JWT filter early so it can populate Authorization header for downstream filters
        http.addFilterBefore(jwtCookieFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
