package com.redpill_linpro.mule.jsonwebtoken;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;
import org.mule.module.json.JsonData;

import com.redpill_linpro.mule.jsonwebtoken.config.ConnectorConfig;

public class JSONWebTokenConnectorTest {

	@Test
	public void verifyDecodePayload() throws IOException {
		ConnectorConfig connectorConfig = new ConnectorConfig();
		connectorConfig.setSecret("secret");
		JSONWebTokenConnector connector = new JSONWebTokenConnector();
		connector.setConfig(connectorConfig);
		
		java.lang.String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmMxMjMifQ.jfr_NOtWZYgvfRfz7W9HPs5jFp8QGcKlPd2P1sKZ4R4";
		JsonData result = connector.decode(token, false);
		assertEquals(result.get("aud").getTextValue(), "abc123");
	}
	
	@Test
	public void verifyDecodeWithValidatePayload() throws IOException {
		ConnectorConfig connectorConfig = new ConnectorConfig();
		connectorConfig.setSecret("secret");
		JSONWebTokenConnector connector = new JSONWebTokenConnector();
		connector.setConfig(connectorConfig);
		
		java.lang.String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmMxMjMifQ.jfr_NOtWZYgvfRfz7W9HPs5jFp8QGcKlPd2P1sKZ4R4";
		JsonData result = connector.decode(token, true);
		assertEquals(result.get("aud").getTextValue(), "abc123");
	}
	
	@Test
	public void verifyDecodeWithValidateNoneAlgPayload() throws IOException {
		ConnectorConfig connectorConfig = new ConnectorConfig();
		connectorConfig.setSecret("secret");
		JSONWebTokenConnector connector = new JSONWebTokenConnector();
		connector.setConfig(connectorConfig);
		
		java.lang.String token = "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhdWQiOiJhYmMxMjMifQ.";
		JsonData result = connector.decode(token, true);
		assertEquals(result.get("aud").getTextValue(), "abc123");
	}
	
	@Test
	public void verifySignatureIsValid() throws IOException {
		ConnectorConfig connectorConfig = new ConnectorConfig();
		connectorConfig.setSecret("secret");
		JSONWebTokenConnector connector = new JSONWebTokenConnector();
		connector.setConfig(connectorConfig);
		
		java.lang.String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmMxMjMifQ.jfr_NOtWZYgvfRfz7W9HPs5jFp8QGcKlPd2P1sKZ4R4";
		
		assertTrue(connector.signatureIsValid(token));
	}

}
