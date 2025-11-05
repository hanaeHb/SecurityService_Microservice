package com.example.service_security.web;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
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
    Map<String, String> login(String username, String password){
        Map<String,String> ID_token = new HashMap<>();
        //verifier authentification
       Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
       );

       //get scope
        String Scope = authenticate.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));
       //creation des 2 id token
       //1 - acess token
        JwtClaimsSet jwtClaimsSet_acessToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(200, ChronoUnit.MINUTES))
                .claim("scope", Scope)
                .build();

        String Acess_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_acessToken)).getTokenValue();

        //2- refresh token
        JwtClaimsSet jwtClaimsSet_refreshToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))
                .build();
        String refresh_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_refreshToken)).getTokenValue();
        ID_token.put("Acecess_Token", Acess_Token);
        ID_token.put("Refresh_token", refresh_Token);
        return ID_token;
    }
    @PostMapping("/refresh")
    public Map<String, String> refresh(String refreshToken){
        Map<String, String> ID_Token = new HashMap<>();

        if(refreshToken == null){
            ID_Token.put("Error", "Refresh token is null" + HttpStatus.UNAUTHORIZED);
            return ID_Token;
        }

        // verifier signature
        Jwt decoder = jwtDecoder.decode(refreshToken);
        String username = decoder.getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // creation access token
        //get scope
        String Scope = userDetails.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));

        //creation des 2 id token
        Instant instant = Instant.now();
        //1 - acess token
        JwtClaimsSet jwtClaimsSet_acessToken = JwtClaimsSet.builder()
                .subject(userDetails.getUsername())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(200, ChronoUnit.MINUTES))
                .claim("scope", Scope)
                .build();

        String Acess_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_acessToken)).getTokenValue();

        ID_Token.put("Acecess_Token", Acess_Token);
        ID_Token.put("Refresh_token", refreshToken);
        return ID_Token;
    }

}
