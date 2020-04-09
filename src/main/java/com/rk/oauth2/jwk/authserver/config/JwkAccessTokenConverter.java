package com.rk.oauth2.jwk.authserver.config;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Map;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

public class JwkAccessTokenConverter extends JwtAccessTokenConverter {

  private Signer signer;
  private String kid;

  private JsonParser objectMapper = JsonParserFactory.create();

  public JwkAccessTokenConverter(KeyPair keyPair, String kid) {
    super();
    super.setKeyPair(keyPair);
    this.signer = new RsaSigner((RSAPrivateKey) keyPair.getPrivate());
    this.kid = kid;
  }

  @Override
  protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

    String content = null;
    try {
      content = objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
    } catch (Exception e) {
      throw new IllegalStateException("Cannot convert access token to JSON", e);
    }

    Map<String, String> customHeaders =
        Collections.singletonMap("kid", kid);
    String token = JwtHelper.encode(content, this.signer, customHeaders).getEncoded();
    return token;
  }
}
