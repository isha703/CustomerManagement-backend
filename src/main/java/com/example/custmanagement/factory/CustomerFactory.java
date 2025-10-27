package com.example.custmanagement.factory;

import com.example.custmanagement.dto.CustomerRequest;
import com.example.custmanagement.model.Customer;

import java.time.Instant;

public class CustomerFactory {
    public static Customer fromRequest(CustomerRequest req) {
        Instant now = Instant.now();
        return Customer.builder()
                .firstName(req.getFirstName())
                .lastName(req.getLastName())
                .email(req.getEmail())
                .phone(req.getPhone())
                .createdBy(req.getCreatedBy())
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    public static void updateFromRequest(Customer customer, CustomerRequest req) {
        customer.setFirstName(req.getFirstName());
        customer.setLastName(req.getLastName());
        customer.setEmail(req.getEmail());
        customer.setPhone(req.getPhone());
        customer.setUpdatedAt(Instant.now());
    }
}
