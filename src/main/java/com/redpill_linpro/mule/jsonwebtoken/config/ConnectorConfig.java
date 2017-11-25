package com.redpill_linpro.mule.jsonwebtoken.config;

import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.param.Optional;


@Configuration(friendlyName = "Configuration")
public class ConnectorConfig {
	
	/**
	 * Specifies a secret/public key for JWT encryption.
	 */
	@Configurable
	@Optional
	private String secret;
	
	public String getSecret() {
		return secret;
	}
	public void setSecret(String secret) {
		this.secret = secret;
	}
}