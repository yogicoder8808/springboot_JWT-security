package com.backend.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    @GetMapping("/customer")
    public String getCustomer() {
        return "Customer content";
    }

    @GetMapping("/info")
    public String getInfo() {
        return "Public info content";
    }
}
