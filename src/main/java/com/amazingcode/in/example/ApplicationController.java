package com.amazingcode.in.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/message")
public class ApplicationController {
    
    @GetMapping
	public String getGreetings(){
		return "Hi User, your welcome here.....";
	}
}
