package com.example.custmanagement.security;

import com.example.custmanagement.model.User;
import com.example.custmanagement.repository.UserRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

@Component
public class JwtCookieAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private static final Logger log = LoggerFactory.getLogger(JwtCookieAuthenticationFilter.class);

    @Value("${app.cookies.secure:false}")
    private boolean cookieSecureOverride;

    public JwtCookieAuthenticationFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        log.debug("JwtCookieAuthenticationFilter path={} method={} CookieHeader={}", path, request.getMethod(), request.getHeader("Cookie"));
        // skip auth endpoints and oauth callbacks to avoid interfering
        if (path.startsWith("/api/auth") || path.startsWith("/oauth2") || path.startsWith("/actuator") || path.startsWith("/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = null;
        String refreshToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            log.debug("Incoming cookies count={}", cookies.length);
            for (Cookie c : cookies) {
                log.debug("cookie {} -> {}", c.getName(), c.getValue() == null ? "<null>" : (c.getValue().length() > 32 ? c.getValue().substring(0, 32) + "..." : c.getValue()));
                if ("access_token".equals(c.getName())) accessToken = c.getValue();
                if ("refresh_token".equals(c.getName())) refreshToken = c.getValue();
            }
        } else {
            log.debug("No Cookie header present on request");
        }

        // If we have an access token, try to decode it. If valid, populate SecurityContext and continue.
        if (accessToken != null && !accessToken.isBlank()) {
            try {
                Jwt jwt = jwtService.decodeJwt(accessToken); // will throw if expired/invalid

                setAuthenticationFromJwt(jwt, request);

                filterChain.doFilter(request, response);
                return;
            } catch (JwtException e) {
                log.debug("Access token invalid/expired: {}", e.getMessage());
                // expired or invalid - attempt refresh if we have a refresh token
            }
        }

        // Attempt refresh token rotation if refresh token present
        if (refreshToken != null && !refreshToken.isBlank()) {
            try {
                String username = jwtService.validateRefreshTokenAndGetSubject(refreshToken);
                Optional<User> ou = userRepository.findByUsername(username);
                if (ou.isPresent()) {
                    User user = ou.get();
                    String newAccess = jwtService.generateAccessToken(user);
                    String newRefresh = jwtService.generateRefreshToken(user);

                    // set cookies using ResponseCookie to include SameSite and avoid duplicate Set-Cookie headers
                    boolean secure = cookieSecureOverride || request.isSecure();
                    String sameSite = secure ? "None" : "Lax";

                    // Use Spring's ResponseCookie builder which produces a proper Set-Cookie header string
                    org.springframework.http.ResponseCookie accessCookie = org.springframework.http.ResponseCookie.from("access_token", newAccess)
                            .httpOnly(true)
                            .secure(secure)
                            .path("/")
                            .maxAge(jwtService.getExpiresIn())
                            .sameSite(sameSite)
                            .build();
                    String accessHeader = accessCookie.toString();
                    response.addHeader("Set-Cookie", accessHeader);
                    response.addHeader("X-Debug-Set-Cookie-Access", accessHeader);
                    log.info("Set access cookie (secure={} sameSite={}) headerPreview={}", secure, sameSite, accessHeader.length() > 128 ? accessHeader.substring(0,128)+"..." : accessHeader);

                    org.springframework.http.ResponseCookie refreshCookie = org.springframework.http.ResponseCookie.from("refresh_token", newRefresh)
                            .httpOnly(true)
                            .secure(secure)
                            .path("/")
                            .maxAge(jwtService.getRefreshExpiresIn())
                            .sameSite(sameSite)
                            .build();
                    String refreshHeader = refreshCookie.toString();
                    response.addHeader("Set-Cookie", refreshHeader);
                    response.addHeader("X-Debug-Set-Cookie-Refresh", refreshHeader);
                    log.info("Set refresh cookie (secure={} sameSite={}) headerPreview={}", secure, sameSite, refreshHeader.length() > 128 ? refreshHeader.substring(0,128)+"..." : refreshHeader);

                    // Build Jwt object for the newly created access token so we can set Authentication
                    Jwt newJwt = jwtService.decodeJwt(newAccess);
                    setAuthenticationFromJwt(newJwt, request);

                    filterChain.doFilter(request, response);
                    return;
                }
            } catch (JwtException ex) {
                log.debug("Refresh token invalid/expired: {}", ex.getMessage());
                // refresh token invalid/expired - fall through and continue without auth
            }
        }

        // No valid tokens - continue unauthenticated
        filterChain.doFilter(request, response);
    }

    private void setAuthenticationFromJwt(Jwt jwt, HttpServletRequest request) {
        String username = jwt.getSubject();
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        Object rolesObj = jwt.getClaims().get("roles");
        if (rolesObj instanceof Collection) {
            ((Collection<?>) rolesObj).forEach(r -> authorities.add(new SimpleGrantedAuthority(r.toString())));
        } else if (rolesObj != null) {
            authorities.add(new SimpleGrantedAuthority(rolesObj.toString()));
        }

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
