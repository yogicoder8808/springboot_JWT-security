package com.backend.security.controller;

import com.backend.security.service.JwtTokenProvider;
import com.backend.security.entity.User;
import com.backend.security.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        if (authentication.isAuthenticated()) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                    .toList();

            String token = jwtTokenProvider.createToken(username, roles);

            return Map.of("token", token);
        } else {
            throw new RuntimeException("Authentication failed");
        }
    }

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        try {
        	user.setRole(user.getRole().toUpperCase());  // Convert role to upper case
            userDetailsService.createUser(user);
            return "User registered successfully!";
        } catch (Exception e) {
            return "Error during registration: " + e.getMessage();
        }
    }
}


