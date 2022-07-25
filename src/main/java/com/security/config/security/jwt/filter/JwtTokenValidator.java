package com.security.config.security.jwt.filter;

import com.security.util.ClaimsUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import lombok.var;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;
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

public class JwtTokenValidator extends OncePerRequestFilter {

    @Value(value = "${secretKey}")
    private String secretKey;

    @Value(value = "${bearer}")
    private String bearer;
    @Value(value = "${headerAuth}")
    private String headerAuth;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(headerAuth);

        if (Strings.isEmpty(authorizationHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!authorizationHeader.startsWith(bearer)) {
            throw new MalformedJwtException(String.format("Invalid token format: %s", authorizationHeader));
        }

        doAuthenticate(request);

        filterChain.doFilter(request, response);

    }

    private void doAuthenticate(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(headerAuth);

        try {
            Claims claims = ClaimsUtil.extractClaims(authorizationHeader);
            String username = getUsername(claims);
            Set<SimpleGrantedAuthority> authorities = getAuthorities(claims);

            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities

            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            throw new MalformedJwtException(String.format("Can not authorize token: %s", authorizationHeader));
        }
    }

    private String getUsername(Claims claims) {
        return claims.getSubject();
    }

    private Set<SimpleGrantedAuthority> getAuthorities(Claims claims) {
        var auth = (List<Map<String, String>>) claims.get("auth");

        return auth.stream().map(map -> new SimpleGrantedAuthority(map.get("authority"))).collect(Collectors.toSet());

    }
}
