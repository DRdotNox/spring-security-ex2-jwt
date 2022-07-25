package com.security.rest.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.util.ClaimsUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

    @Value(value = "${secretKey}")
    private String secretKey;

    @Value(value = "${accessTokenHeader}")
    private String accessTokenHeader;

    @Value(value = "${refreshTokenHeader}")
    private String refreshTokenHeader;

    @Value(value = "${bearer}")
    private String bearer;

    @PostMapping
    public ResponseEntity refresh(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authHeader = request.getHeader(accessTokenHeader);
        if (authHeader == null || !authHeader.startsWith(bearer)) {
            throw new RuntimeException("Refresh token is missing");
        }

        Claims claims = ClaimsUtil.extractClaims(authHeader);

        response.setHeader(refreshTokenHeader, generateRefreshToken(claims));
        response.setHeader(accessTokenHeader, generateAccessToken(claims));
        return ResponseEntity.ok().build();

    }

    private String generateAccessToken(Claims claims) {

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(Date.valueOf(LocalDate.now().plusDays(1)))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
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
