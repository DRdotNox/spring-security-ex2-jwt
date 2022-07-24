package com.security.config.security.jwt.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.var;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtRefreshTokenValidator extends OncePerRequestFilter {

    private final String secretKey = "reallySecureKeyreallySecureKeyreallySecureKeyreallySecureKey";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String refreshTokenHeader = request.getHeader("X-Refresh-Token");

        if (Strings.isEmpty(refreshTokenHeader)) {
            throw new JwtException("RefreshToken is empty");
        }

        if (!refreshTokenHeader.startsWith("Bearer ")) {
            throw new MalformedJwtException(String.format("Invalid token format: %s", refreshTokenHeader));
        }

        doAuthenticate(request);

        filterChain.doFilter(request, response);

    }

    private void doAuthenticate(HttpServletRequest request) {
        String refreshTokenHeader = request.getHeader("X-Refresh-Token");

        try {

            Claims claims = extractClaims(refreshTokenHeader);
            String username = getUsername(claims);
            Set<SimpleGrantedAuthority> authorities = getAuthorities(claims);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities

            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            throw new MalformedJwtException(String.format("Can not authorize token: %s", refreshTokenHeader));
        }
    }

    private String getUsername(Claims claims) {
        return claims.getSubject();
    }

    private Set<SimpleGrantedAuthority> getAuthorities(Claims claims) {
        var auth = (List<Map<String, String>>) claims.get("auth");

        return auth.stream()
                .map(map -> new SimpleGrantedAuthority(map.get("authority")))
                .collect(Collectors.toSet());

    }

    private Claims extractClaims(String authorizationHeader) {
        String token = extractToken(authorizationHeader);
        JwtParserBuilder jwtParserBuilder = Jwts.parserBuilder();
        jwtParserBuilder.setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()));
        Jws<Claims> jws = jwtParserBuilder.build().parseClaimsJws(token);
        Claims claims = jws.getBody();

        if (claims
                .getExpiration()
                .before(
                        Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC))
                )
        ) {
            throw new ExpiredJwtException(jws.getHeader(), jws.getBody(), "JWT token is expired");
        }

        return claims;
    }

    private String extractToken(String authorizationHeader) {

        return authorizationHeader.replace("Bearer ", "");
    }
}
