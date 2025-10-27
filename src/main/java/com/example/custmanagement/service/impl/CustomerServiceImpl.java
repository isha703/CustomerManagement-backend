package com.example.custmanagement.service.impl;

import com.example.custmanagement.dto.CustomerRequest;
import com.example.custmanagement.dto.CustomerResponse;
import com.example.custmanagement.factory.CustomerFactory;
import com.example.custmanagement.model.Customer;
import com.example.custmanagement.repository.CustomerRepository;
import com.example.custmanagement.service.CustomerService;
import com.example.custmanagement.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class CustomerServiceImpl implements CustomerService {
    private static final Logger log = LoggerFactory.getLogger(CustomerServiceImpl.class);

    private final CustomerRepository repository;
    private final JwtService jwtService;


    @Override
    public CustomerResponse createCustomer(CustomerRequest request) {
        log.debug("createCustomer called, security auth={}", SecurityContextHolder.getContext() == null ? null : SecurityContextHolder.getContext().getAuthentication());
        Optional<Customer> existing = repository.findByEmail(request.getEmail());
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Customer with email already exists");
        }

        Customer customer = CustomerFactory.fromRequest(request);
        // set audit info


       // if (currentUser != null) customer.setCreatedBy(currentUser);
        Instant now = Instant.now();
        customer.setCreatedAt(now);
        customer.setUpdatedAt(now);

        Customer saved = repository.save(customer);
        log.debug("Customer created id={} createdBy={}", saved.getId(), saved.getCreatedBy());
        return toResponse(saved);
    }

    @Override
    public CustomerResponse updateCustomer(Long id, CustomerRequest request) {
        log.debug("updateCustomer called id={} security auth={}", id,
                SecurityContextHolder.getContext() == null ? null : SecurityContextHolder.getContext().getAuthentication());

        Customer customer = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Customer not found"));

        // Check if another customer already has the requested email
        Optional<Customer> existing = repository.findByEmail(request.getEmail());
        if (existing.isPresent() && !existing.get().getId().equals(id)) {

            throw new IllegalArgumentException("Customer with email already exists");
        }


        CustomerFactory.updateFromRequest(customer, request);


        customer.setUpdatedAt(Instant.now());

        Customer saved = repository.save(customer);
        log.debug("Customer updated id={} createdBy={}", saved.getId(), saved.getCreatedBy());

        return toResponse(saved);
    }

    @Override
    public boolean deleteCustomer(Long id) {
        if (!repository.existsById(id)) return false; // Customer not found
        repository.deleteById(id);
        return true;
    }

    private CustomerResponse toResponse(Customer c) {
        return CustomerResponse.builder()
                .id(c.getId())
                .firstName(c.getFirstName())
                .lastName(c.getLastName())
                .email(c.getEmail())
                .phone(c.getPhone())
                .createdAt(c.getCreatedAt())
                .updatedAt(c.getUpdatedAt())
                .createdBy(c.getCreatedBy())
                .encryptedId(jwtService.encryptPayload(String.valueOf(c.getId())))
                .build();
    }


}