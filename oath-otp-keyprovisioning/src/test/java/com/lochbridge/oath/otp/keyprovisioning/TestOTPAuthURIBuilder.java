package com.lochbridge.oath.otp.keyprovisioning;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.lochbridge.oath.otp.HOTPBuilder;
import com.lochbridge.oath.otp.TOTPBuilder;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;

public class TestOTPAuthURIBuilder {
    
    private static final OTPKey totpKey = new OTPKey("123", OTPType.TOTP);
    private static final OTPKey hotpKey = new OTPKey(totpKey.getKey(), OTPType.HOTP);
    private static final String ISSUER = "Acme Corporation";
    private static final String ISSUER_ENC = "Acme%20Corporation";
    private static final String ACCOUNT_NM = "Alice Smith";
    private static final String ACCOUNT_NM_ENC = "Alice%20Smith";
    private static final String LABEL = String.format("%s:%s", ISSUER, ACCOUNT_NM);
    private static final int DIGITS = 6;
    private static final int COUNTER = 5;
    private static final long TIMESTEP_SEC = 30;
    private static final long TIMESTEP_MS = TimeUnit.SECONDS.toMillis(TIMESTEP_SEC);

    @Test(expected = NullPointerException.class)
    public void keyShouldFailWhenArgumentIsNull() {
        OTPAuthURIBuilder.key(null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void issuerShouldFailWhenALiteralColonIsPresent() {
        OTPAuthURIBuilder.key(totpKey).issuer("foo:bar");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void issuerShouldFailWhenAnURLEncodedColonIsPresent() {
        OTPAuthURIBuilder.key(totpKey).issuer("foo%3Abar");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void digitsForTOTPUriShouldFailWhenOutOfAllowedRange() {
        OTPAuthURIBuilder.key(totpKey).digits(TOTPBuilder.MAX_ALLOWED_DIGITS + 1);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void digitsForHOTPUriShouldFailWhenOutOfAllowedRange() {
        OTPAuthURIBuilder.key(hotpKey).digits(HOTPBuilder.MAX_ALLOWED_DIGITS + 1);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void counterShouldFailWhenArgumentIsLessThanZero() {
        OTPAuthURIBuilder.key(hotpKey).counter(-1);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void timeStepShouldFailWhenArgumentIsZer() {
        OTPAuthURIBuilder.key(totpKey).timeStep(0);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void timeStepShouldFailWhenArgumentIsLessThanZero() {
        OTPAuthURIBuilder.key(totpKey).timeStep(-1);
    }
    
    @Test(expected = NullPointerException.class)
    public void buildShouldFailWhenLabelArgumentIsNull() {
        OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(null, true);
    }
    
    @Test
    public void buildShouldFailWhenLabelAccountNameIsEmpty() {
        try {
            OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build("   ", true);
            fail("The build call should have failed when the label's account name is missing/empty!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
        
        try {
            OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(ISSUER + ":   ", true);
            fail("The build call should have failed when the label's account name is empty!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void buildShouldFailWhenLabelAccountNameIsMissing() {
        OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(ISSUER + ":", true);
    }
    
    @Test
    public void buildShouldFailWhenLabelAccountNameContainsALiteralColon() {
        try {
            OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(":foobar", true);
            fail("The build call should have failed when the label's account name contains a literal colon!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
        
        try {
            OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(ISSUER + ":foo:bar", true);
            fail("The build call should have failed when the label's account name contains a literal colon!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void buildShouldFailWhenIssuerAndLabelAccountNameAreDifferent() {
        OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(ISSUER + "1:foobar", true);
    }
    
    @Test
    public void buildTOTPUriShouldSucceed() {
        OTPAuthURI uri = OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(LABEL, true);
        String expected = String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d", LABEL, totpKey.getKey(), ISSUER, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toPlainTextUriString());
        expected = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), 
                ISSUER_ENC, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        
        // Only label is encoded.
        uri = OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).omitIssuerEncoding().digits(DIGITS).timeStep(TIMESTEP_MS).build(LABEL, true);
        expected = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), 
                ISSUER, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        
        // Ensure's includeIssuerEncoding() behaves as expected.
        uri = OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).omitIssuerEncoding().includeIssuerEncoding().digits(DIGITS).timeStep(TIMESTEP_MS).build(LABEL, true);
        expected = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), 
                ISSUER_ENC, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        
        // No issuer and label encoding.
        uri = OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).omitIssuerEncoding().digits(DIGITS).timeStep(TIMESTEP_MS).build(LABEL, false);
        expected = String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d", LABEL, totpKey.getKey(), ISSUER, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        assertEquals(uri.toPlainTextUriString(), uri.toUriString());
        
        // No label issuer prefix.
        uri = OTPAuthURIBuilder.key(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build(ACCOUNT_NM, true);
        expected = String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d", ACCOUNT_NM_ENC, totpKey.getKey(), 
                ISSUER_ENC, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        
        // No issuer parameter.
        uri = OTPAuthURIBuilder.key(totpKey).issuer(null).digits(DIGITS).timeStep(TIMESTEP_MS).build(LABEL, true);
        expected = String.format("otpauth://totp/%s:%s?secret=%s&digits=%d&period=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), 
                DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
    }
    
    @Test
    public void buildHOTPUriShouldSucceed() {
        OTPAuthURI uri = OTPAuthURIBuilder.key(hotpKey).issuer(ISSUER).digits(DIGITS).counter(COUNTER).build(LABEL, true);
        String expected = String.format("otpauth://hotp/%s?secret=%s&issuer=%s&digits=%d&counter=%d", LABEL, hotpKey.getKey(), ISSUER, DIGITS, COUNTER);
        assertEquals(expected, uri.toPlainTextUriString());
        expected = String.format("otpauth://hotp/%s:%s?secret=%s&issuer=%s&digits=%d&counter=%d", ISSUER_ENC, ACCOUNT_NM_ENC, hotpKey.getKey(), 
                ISSUER_ENC, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        
        // Only label is encoded.
        uri = OTPAuthURIBuilder.key(hotpKey).issuer(ISSUER).omitIssuerEncoding().digits(DIGITS).counter(COUNTER).build(LABEL, true);
        expected = String.format("otpauth://hotp/%s:%s?secret=%s&issuer=%s&digits=%d&counter=%d", ISSUER_ENC, ACCOUNT_NM_ENC, hotpKey.getKey(), 
                ISSUER, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        
        // Ensure's includeIssuerEncoding() behaves as expected.
        uri = OTPAuthURIBuilder.key(hotpKey).issuer(ISSUER).omitIssuerEncoding().includeIssuerEncoding().digits(DIGITS).counter(COUNTER).build(LABEL, true);
        expected = String.format("otpauth://hotp/%s:%s?secret=%s&issuer=%s&digits=%d&counter=%d", ISSUER_ENC, ACCOUNT_NM_ENC, hotpKey.getKey(), 
                ISSUER_ENC, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        
        // No issuer and label encoding.
        uri = OTPAuthURIBuilder.key(hotpKey).issuer(ISSUER).omitIssuerEncoding().digits(DIGITS).counter(COUNTER).build(LABEL, false);
        expected = String.format("otpauth://hotp/%s?secret=%s&issuer=%s&digits=%d&counter=%d", LABEL, hotpKey.getKey(), ISSUER, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        assertEquals(uri.toPlainTextUriString(), uri.toUriString());
        
        // No label issuer prefix.
        uri = OTPAuthURIBuilder.key(hotpKey).issuer(ISSUER).digits(DIGITS).counter(COUNTER).build(ACCOUNT_NM, true);
        expected = String.format("otpauth://hotp/%s?secret=%s&issuer=%s&digits=%d&counter=%d", ACCOUNT_NM_ENC, totpKey.getKey(), ISSUER_ENC, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        
        // No issuer parameter.
        uri = OTPAuthURIBuilder.key(hotpKey).issuer(null).digits(DIGITS).counter(COUNTER).build(LABEL, true);
        expected = String.format("otpauth://hotp/%s:%s?secret=%s&digits=%d&counter=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
    }

}
