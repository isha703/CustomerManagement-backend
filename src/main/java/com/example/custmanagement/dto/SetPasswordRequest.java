package com.example.custmanagement.dto;

public  class SetPasswordRequest {
    private String email;
    private String data; // encrypted password

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
}