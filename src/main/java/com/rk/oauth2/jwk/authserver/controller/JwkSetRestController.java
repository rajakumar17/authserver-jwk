package com.rk.oauth2.jwk.authserver.controller;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwkSetRestController {

  @Autowired
  private JWKSet jwkSet;

  @GetMapping("/.well-known/jwks.json")
  public Map<String, Object> keys() {
    return this.jwkSet.toJSONObject();
  }

}
