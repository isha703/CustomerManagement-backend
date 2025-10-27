package com.example.custmanagement.security;

import com.example.custmanagement.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final JwtService jwtService;
    private final UserService userService;

    @Value("${APP_TOKEN_REDIRECT:}")
    private String tokenRedirect;

    @Value("${app.cookies.secure:false}")
    private boolean cookieSecureOverride;

    public CustomAuthenticationSuccessHandler(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        try {
            if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unsupported authentication type");
                return;
            }

            OAuth2User oauthUser = oauth2Token.getPrincipal();

            // --- Fetch or create user ---
            com.example.custmanagement.model.User localUser = userService.createUserIfNotExistsFromOAuth(oauthUser);
            if (localUser == null) {
                throw new IllegalStateException("UserService returned null user");
            }

            // --- Generate JWT tokens ---
            String accessToken = jwtService.generateAccessToken(localUser);
            String refreshToken = jwtService.generateRefreshToken(localUser);

            boolean secure = request.isSecure() || cookieSecureOverride;
            String sameSite = secure ? "None" : "Lax";

            addCookieHeader(response, "access_token", accessToken, (int) jwtService.getExpiresIn(), secure, sameSite);
            addCookieHeader(response, "refresh_token", refreshToken, (int) jwtService.getRefreshExpiresIn(), secure, sameSite);

            // Remove OAuth2 request cookie
            addCookieHeader(response, HttpCookieOAuth2AuthorizationRequestRepository.OAUTH2_AUTH_REQUEST_COOKIE_NAME, "", 0, secure, sameSite);

            // --- Redirect to frontend (cookie-only) ---
            String redirectUrl = buildRedirectUrl(tokenRedirect);

            response.sendRedirect(redirectUrl);
            log.info("Redirecting user to frontend callback (cookies set) to {}", redirectUrl);
        } catch (Exception e) {
            log.error("OAuth2 login failed", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OAuth2 login failed: " + e.getMessage());
        }
    }


    private void addCookieHeader(HttpServletResponse response, String name, String value, int maxAge, boolean secure, String sameSite) {
        // Use ResponseCookie to ensure proper formatting including SameSite
        org.springframework.http.ResponseCookie cookie = org.springframework.http.ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(sameSite)
                .build();
        String header = cookie.toString();
        response.addHeader("Set-Cookie", header);
        response.addHeader("X-Debug-Set-Cookie-" + name, header);
        log.debug("Set cookie {} (secure={} sameSite={}) headerPreview={}", name, secure, sameSite, header.length() > 128 ? header.substring(0,128)+"..." : header);
    }

    private String buildRedirectUrl(String tokenRedirect) {
        String frontend = (tokenRedirect != null && !tokenRedirect.isBlank()) ? tokenRedirect : "http://localhost:8081";
        try {
            java.net.URI uri = new java.net.URI(frontend);
            StringBuilder origin = new StringBuilder();
            origin.append(uri.getScheme()).append("://").append(uri.getHost());
            if (uri.getPort() != -1) origin.append(":").append(uri.getPort());
            frontend = origin.toString();
        } catch (Exception ignored) {}
        return frontend.endsWith("/") ? frontend + "oauth-callback" : frontend + "/oauth-callback";
    }

}
