package com.zerodaycode.summonerssync.apigateway.security;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

//@Data
public class Roles {
    private final List<String> roles;
    public Roles() { this.roles = new ArrayList<>(); }
    public Roles(List<String> roles) { this.roles = roles; }
    public List<String> getRoles() { return roles; }

}
