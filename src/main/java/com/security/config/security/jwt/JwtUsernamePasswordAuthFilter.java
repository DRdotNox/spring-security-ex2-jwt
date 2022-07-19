package com.security.config.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Date;
import java.time.LocalDate;

@RequiredArgsConstructor
public class JwtUsernamePasswordAuthFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        try {
            UsernamePasswordAuthRequest authRequest = new ObjectMapper()
                    .readValue(request.getInputStream(),UsernamePasswordAuthRequest.class);
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

            String token = generateJwtToken(authResult);

            response.addHeader("X-Auth-Token", "Bearer " + token);

        super.successfulAuthentication(request, response, chain, authResult);
    }


    private String generateJwtToken(Authentication authResult) {
        return Jwts.builder()
                .setSubject(authResult.getName()) //claim sub
                .claim("auth", authResult.getAuthorities()) // claim auth
                .setExpiration(Date.valueOf(LocalDate.now().plusDays(1))) // claim expDate
                .signWith(Keys.hmacShaKeyFor("reallySecureKey".getBytes())) //signature
                .compact();
    }
}
