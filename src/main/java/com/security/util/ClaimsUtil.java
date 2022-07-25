package com.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class ClaimsUtil {
    @Value(value = "${secretKey}")
    private static String secretKey;
    @Value(value = "${bearer}")
    private static String bearer;

    public static Claims extractClaims(String authorizationHeader) {
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

    private static String extractToken(String authorizationHeader) {

        return authorizationHeader.replace(bearer, "");
    }
}
