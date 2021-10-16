package com.myeshop.ApiGateway.config;

import lombok.Data;

@Data
public class CustomPrincipal {
    private String uid;
    private String email;
}
