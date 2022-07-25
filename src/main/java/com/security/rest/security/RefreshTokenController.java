package com.security.rest.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Date;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/refresh_token")
public class RefreshTokenController {

    private final String secretKey = "reallySecureKeyreallySecureKeyreallySecureKeyreallySecureKey";


    private final UserDetailsService userDetailsService;

    @Autowired
    public RefreshTokenController(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @PostMapping
    public ResponseEntity refresh(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authHeader = request.getHeader("X-Refresh-Token");
        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            throw new RuntimeException("Refresh token is missing");
        }

        Claims claims = extractClaims(authHeader);

        response.setHeader("X-Refresh-Token", generateRefreshToken(claims));
        response.setHeader("X-Access_Token", generateAccessToken(claims));

        return ResponseEntity.ok().build();

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

    private String generateAccessToken(Claims claims) {

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(Date.valueOf(LocalDate.now().plusDays(1))) // claim expDate
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes())) //signature
                .compact();
    }

    private String generateRefreshToken(Claims claims) {

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(Date.valueOf(LocalDate.now().plusWeeks(1)))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }
}
