package com.security.config.security.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.config.security.jwt.UsernamePasswordAuthRequest;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Date;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;


public class JwtUsernamePasswordAuthFilter extends AbstractAuthenticationProcessingFilter {

    private final String secretKey = "reallySecureKeyreallySecureKeyreallySecureKeyreallySecureKey";

    private AuthenticationManager authManager;

    public JwtUsernamePasswordAuthFilter(AuthenticationManager authManager) {
        super("/api/v1/auth");
        this.authManager = authManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {


        try {
            UsernamePasswordAuthRequest authRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernamePasswordAuthRequest.class);
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    authRequest.getUsername(),
                    authRequest.getPassword()
            );

            return authManager.authenticate(auth);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

//        String accessToken = generateAccessToken(authResult);
//        String refreshToken = generateRefreshToken(authResult);
//
//        response.addHeader("Authorization", "Bearer " + accessToken);
//        response.addHeader("Authorization", "Bearer " + refreshToken);
        generateBody( response,authResult);


    }

    private void generateBody(HttpServletResponse response, Authentication authResult) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", generateAccessToken(authResult));
        tokens.put("refresh_token", generateRefreshToken(authResult));

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }


    private String generateAccessToken(Authentication authResult) {

        return Jwts.builder()
                .setSubject(authResult.getName()) //claim sub
                .claim("auth", authResult.getAuthorities()) // claim auth
                .setExpiration(Date.valueOf(LocalDate.now().plusDays(1))) // claim expDate
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes())) //signature
                .compact();
    }

    private String generateRefreshToken(Authentication authResult) {

        return Jwts.builder()
                .setSubject(authResult.getName())
                .setExpiration(Date.valueOf(LocalDate.now().plusWeeks(1)))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }
}
