package com.redpill_linpro.mule.jsonwebtoken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Filter;
import org.mule.api.annotations.Mime;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.param.Default;
import org.mule.module.json.JsonData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.redpill_linpro.mule.jsonwebtoken.config.ConnectorConfig;

/**
 * JSON Web Token Connector for Mule Runtime.
 * @author Redpill Linpro
 */
@Connector(name="jwt", friendlyName="JSON Web Token", 
    minMuleVersion="3.8.0",
	description="JSON Web Token decoding and validation")
public class JSONWebTokenConnector {

    @Config
    ConnectorConfig config;
    
	private static final Logger LOG = LoggerFactory.getLogger(JSONWebTokenConnector.class);


    /**
     * Decode JWT into a JsonData
     *
     * @param token The JSON Web Token to decode
     * @param validateSignature If the JSON Web Token should be validated before decoded
     * @return A JSONObject containing the claims from the JSON Web Token payload
     * @throws IOException If we are not able to parse the JSON Web Token header or payload. 
     */
    @Processor(friendlyName="Decode JWT")
    @Mime("application/json")
    public JsonData decode(@Default("#[message.inboundProperties['Authorization']]") String token, @Default("false") Boolean validateSignature) throws IOException {
    	String[] jwtParts = splitToken(token);
    	if ( !validateSignature || doValidate(jwtParts)) {
    		JsonData jwtPayload = new JsonData(new ByteArrayInputStream(Base64.getDecoder().decode(jwtParts[1])));
    		return jwtPayload;
    	} else {
    		throw new RuntimeException("Invalid JSON Token");
    	}
    }

    
    /**
     * Validates a JWT 
     * @param token The JSON Web Token to validate
     * @return <code>true</code> if the provide token has none or valid signature 
     * @throws IOException If we are not able to parse the JSON Web Token header or payload.
     */
    @Filter
    public boolean signatureIsValid(
    		@Default("#[message.inboundProperties['Authorization']]") String token) throws IOException {
    	
    	String[] jwtParts = splitToken(token);
    	
    	return doValidate(jwtParts);
    }


	private boolean doValidate(final String[] jwtParts) throws IOException {
		JsonData jwtHeader = new JsonData(new ByteArrayInputStream(Base64.getDecoder().decode(jwtParts[0])));
		if ( !("JWT".equals(jwtHeader.get("typ"))) && jwtHeader.get("alg") == null ) {
			LOG.debug("JWT signature could not be verified: No algorithm specified");				
			
		} else {
			String algHeader = jwtHeader.get("alg").getTextValue();
            if (algHeader.startsWith("NONE") ) {
            	return true;
			} else if ( algHeader.startsWith("RS") ) {
				return verifyRSASignature(algHeader, jwtParts);
			} else if ( algHeader.startsWith("HS") ) {
				return verifyHMACSHASignature(algHeader, jwtParts);
			} else {
				LOG.debug("JWT signature could not be verified: No known algorithm: " + algHeader);
			}
		}
		return false;
	}

	private boolean verifyHMACSHASignature(final String algHeader, final String[] jwtParts) {
		
		String algorithm;
		switch (algHeader) {
			case "HS256":
				algorithm = "HmacSHA256";
				break;
			case "HS384":
				algorithm = "HmacSHA384";
				break;
			case "HS512":
				algorithm = "HmacSHA512";
				break;	
			default:
				algorithm = null;
		}
		boolean verified = false;
		try {
			if (algorithm != null){
				Mac shaHMAC = Mac.getInstance(algorithm);
				SecretKeySpec secret_key = new SecretKeySpec(config.getSecret().getBytes(), algorithm);
				shaHMAC.init(secret_key);
				byte[] calculatedSignature = shaHMAC.doFinal((jwtParts[0] + '.' + jwtParts[1]).getBytes());
				byte[] recivedSignature = Base64.getUrlDecoder().decode(jwtParts[2]);
				verified = Arrays.equals(calculatedSignature, recivedSignature);
			}
			else{
				LOG.debug("JWT signature could not be verified: No known algorithm: " + algHeader);				
			}
		} catch (Exception e) {
			LOG.debug("JWT signature could not be verified: " + e);				
			verified = false;
		}
		return verified;
	}


	private boolean verifyRSASignature(final String algHeader, final String[] jwtParts) {
		String algorithm = null;
		
		switch ( algHeader ) {
			case "RS256":
				algorithm = "SHA256withRSA";
				break;
						
			case "RS384":
				algorithm = "SHA384withRSA";
				break;
						
			case "RS512":
				algorithm = "SHA512withRSA";
				break;												
		}
		boolean verified = false;
		try {					
			byte[] pk = Base64.getDecoder().decode(config.getSecret());
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pk); 
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);		
			Signature signature = Signature.getInstance(algorithm);				
			signature.initVerify(publicKey);
			signature.update((jwtParts[0] + '.' + jwtParts[1]).getBytes());											
			
			verified = signature.verify(Base64.getDecoder().decode(jwtParts[2]));						
		} catch (Exception e){
			LOG.debug("JWT signature could not be verified: " + e);				
			verified = false;
		}
		return verified;
	}
    
    private String[] splitToken(String token) {
    	// If the token header value starts with "Bearer " then remove that part
    	if ( StringUtils.startsWith(token, "Bearer ")) {
        	token = token.substring(token.indexOf(' ') + 1);
        }
    	return token.split("\\.", 3);
    }
    
    
    public ConnectorConfig getConfig() {
        return config;
    }

    public void setConfig(ConnectorConfig config) {
        this.config = config;
    }

}