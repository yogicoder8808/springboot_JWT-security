package com.backend.security.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.backend.security.entity.User;
import com.backend.security.repository.UserRepository;

@RestController
@RequestMapping("/api/v1")
public class UserController {

	 @Autowired
	    private UserRepository userRepository;

	    @GetMapping("/customer")
	    public List<User> getCustomer() {
	        return userRepository.findAll();
	    }

    @GetMapping("/info")
    public String getInfo() {
        return "Public info content";
    }
}
