package com.theelixrlabs.User.service;

import com.theelixrlabs.User.constants.UserConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class JwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private String secretKey;

    public JwtService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(UserConstant.HMAC_ALGORITHM);
            SecretKey sk = keyGen.generateKey();
            secretKey = Base64.getEncoder().encodeToString(sk.getEncoded());
            logger.debug("JWT Secret key generated successfully.");  // DEBUG log for key generation
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error generating JWT secret key", e);  // ERROR log for key generation failure
            throw new RuntimeException(e);
        }
    }

    public String generateToken(String username) {
        logger.info("Generating token for user: {}", username);  // INFO log for token generation
        Map<String, Object> claims = new HashMap<>();
        String token = Jwts.builder()
                .setClaims(claims)  // Corrected: use setClaims() instead of claims()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))  // 1-hour validity
                .signWith(getKey())
                .compact();
        logger.debug("Token generated successfully for user: {}", username);  // DEBUG log for token generation
        return token;
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        logger.info("Extracting username from token");  // INFO log for extracting username
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()  // Corrected: use parserBuilder() instead of parser()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        logger.debug("Validating token for user: {}", userName);  // DEBUG log for token validation
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}