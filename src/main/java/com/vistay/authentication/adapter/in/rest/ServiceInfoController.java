package com.vistay.authentication.adapter.in.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/internal")
public class ServiceInfoController {

    @GetMapping("/service-info")
    public Map<String, String> serviceInfo() {
        return Map.of("name", "authentication", "version", "0.1.0");
    }
}
