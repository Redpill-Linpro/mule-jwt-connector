package com.redpill_linpro.mule.jsonwebtoken.automation.functional;

import static org.junit.Assert.*;

import java.io.IOException;

import com.redpill_linpro.mule.jsonwebtoken.JSONWebTokenConnector;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mule.module.json.JsonData;
import org.mule.tools.devkit.ctf.junit.AbstractTestCase;

public class DecodePayloadTestCases extends AbstractTestCase<JSONWebTokenConnector> {

	public DecodePayloadTestCases() {
		super(JSONWebTokenConnector.class);
	}

	@Before
	public void setup() {
		// TODO
	}

	@After
	public void tearDown() {
		// TODO
	}

	@Test
	public void verifyDecodePayload() throws IOException {
		java.lang.String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmMxMjMifQ.jfr_NOtWZYgvfRfz7W9HPs5jFp8QGcKlPd2P1sKZ4R4";
		JsonData result = getConnector().decodePayload(token, false);
		assertEquals(result.get("aud").getTextValue(), "abc123");
	}

}