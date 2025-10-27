package com.example.custmanagement.controller;

import com.example.custmanagement.dto.CustomerRequest;
import com.example.custmanagement.dto.CustomerResponse;
import com.example.custmanagement.model.Customer;
import com.example.custmanagement.service.CustomerService;
import com.example.custmanagement.repository.CustomerRepository;
import com.example.custmanagement.security.JwtService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/customers")
@RequiredArgsConstructor
public class CustomerController {
    private final CustomerService service;
    private final CustomerRepository repo;
    private final JwtService jwtService;

//    @PostMapping("/add")
//    @PreAuthorize("isAuthenticated()")
//    public ResponseEntity<CustomerResponse> create(@Valid @RequestBody CustomerRequest req, java.security.Principal principal) {
//        String creator = principal == null ? null : principal..getName();
//        CustomerResponse res = service.createCustomer(req, creator);
//        return ResponseEntity.status(HttpStatus.CREATED).body(res);
//    }

    @PostMapping("/add")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<CustomerResponse> create(@Valid @RequestBody CustomerRequest req, java.security.Principal principal) {


        CustomerResponse res = service.createCustomer(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(res);
    }

    @PutMapping("/update")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<CustomerResponse> update(@RequestParam("eid") String encryptedId, @Valid @RequestBody CustomerRequest req) {
        if (encryptedId == null || encryptedId.isBlank()) return ResponseEntity.badRequest().build();
        try {
            String decrypted = jwtService.decryptPayload(encryptedId);
            Long id = Long.parseLong(decrypted);
            CustomerResponse res = service.updateCustomer(id, req);
            return ResponseEntity.ok(res);
        } catch (NumberFormatException nfe) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @DeleteMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> delete(@RequestParam("eid") String encryptedId) {
        if (encryptedId == null || encryptedId.isBlank()) return ResponseEntity.badRequest().build();
        try {
            String decrypted = jwtService.decryptPayload(encryptedId);
            Long id = Long.parseLong(decrypted);
            service.deleteCustomer(id);
            return ResponseEntity.noContent().build();
        } catch (NumberFormatException nfe) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("data")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<Customer>> getCustomersByUser(@RequestParam("email") String email) {
        if (email == null || email.isBlank()) return ResponseEntity.badRequest().build();
        List<Customer> customers = repo.findByCreatedBy(email);
        return ResponseEntity.ok(customers);
    }
}
