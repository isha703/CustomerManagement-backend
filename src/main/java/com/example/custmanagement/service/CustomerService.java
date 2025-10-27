package com.example.custmanagement.service;

import com.example.custmanagement.dto.CustomerRequest;
import com.example.custmanagement.dto.CustomerResponse;

public interface CustomerService {


    CustomerResponse createCustomer(CustomerRequest request);
    CustomerResponse updateCustomer(Long id, CustomerRequest request);
    boolean deleteCustomer(Long id);
}
