package com.example.demo.paylaod;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class ApiResponse {

    private boolean success;

    private String message;

}
