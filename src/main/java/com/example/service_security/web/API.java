package com.example.service_security.web;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class API {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private UserDetailsService userDetailsService;

    public API(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    Instant instant = Instant.now();
    private AuthenticationManager authenticationManager;
    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username,
                                     @RequestParam String password) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        String scope = authentication.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.joining(" "));

        Instant now = Instant.now();

        var claims = JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuer("Security_Service")
                .issuedAt(now)
                .expiresAt(now.plus(200, ChronoUnit.MINUTES))
                .claim("scope", scope)
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        var refreshClaims = JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuer("Security_Service")
                .issuedAt(now)
                .expiresAt(now.plus(15, ChronoUnit.MINUTES))
                .build();

        String refreshToken = jwtEncoder.encode(JwtEncoderParameters.from(refreshClaims)).getTokenValue();

        return Map.of("access_token", accessToken, "refresh_token", refreshToken);
    }
    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestParam String refreshToken) {
        Map<String, String> tokens = new HashMap<>();

        if (refreshToken == null) {
            tokens.put("Error", "Refresh token is null");
            return tokens;
        }

        try {
            Jwt decoded = jwtDecoder.decode(refreshToken);

            if (decoded.getExpiresAt().isBefore(Instant.now())) {
                tokens.put("Error", "Refresh token expired");
                return tokens;
            }

            String username = decoded.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            String scope = userDetails.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .collect(Collectors.joining(" "));

            Instant now = Instant.now();
            JwtClaimsSet accessClaims = JwtClaimsSet.builder()
                    .subject(userDetails.getUsername())
                    .issuer("Security_Service")
                    .issuedAt(now)
                    .expiresAt(now.plus(200, ChronoUnit.MINUTES))
                    .claim("scope", scope)
                    .build();

            String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(accessClaims)).getTokenValue();

            tokens.put("access_token", accessToken);
            tokens.put("refresh_token", refreshToken);
        } catch (JwtException e) {
            tokens.put("Error", "Invalid refresh token");
        }

        return tokens;
    }


}
