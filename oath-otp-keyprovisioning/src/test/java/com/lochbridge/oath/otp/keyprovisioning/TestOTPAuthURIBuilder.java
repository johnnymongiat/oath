package com.lochbridge.oath.otp.keyprovisioning;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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
    public void fromKeyShouldFailWhenArgumentIsNull() {
        OTPAuthURIBuilder.fromKey(null);
    }
    
    @Test(expected = NullPointerException.class)
    public void labelShouldFailWhenArgumentIsNull() {
        OTPAuthURIBuilder.fromKey(totpKey).label(null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void labelShouldFailWhenAccountNameIsMissing() {
        OTPAuthURIBuilder.fromKey(totpKey).label(ISSUER + ":");
    }
    
    @Test
    public void labelShouldFailWhenAccountNameIsEmpty() {
        try {
            OTPAuthURIBuilder.fromKey(totpKey).label("   ");
            fail("The label call should have failed when the label's account name is empty!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
        
        try {
            OTPAuthURIBuilder.fromKey(totpKey).label(ISSUER + ":   ");
            fail("The label call should have failed when the label's account name is empty!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
    }
    
    public void labelShouldFailWhenAccountNameContainsALiteralColon() {
        try {
            OTPAuthURIBuilder.fromKey(totpKey).label(":foobar");
            fail("The label call should have failed when the label's account name contains a literal colon!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
        
        try {
            OTPAuthURIBuilder.fromKey(totpKey).label(ISSUER + ":foo:bar");
            fail("The label call should have failed when the label's account name contains a literal colon!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
        
        try {
            OTPAuthURIBuilder.fromKey(totpKey).label("foo:bar:baz");
            fail("The label call should have failed when the label's account name contains a literal colon!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void issuerShouldFailWhenALiteralColonIsPresent() {
        OTPAuthURIBuilder.fromKey(totpKey).issuer("foo:bar");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void digitsForTOTPUriShouldFailWhenOutOfAllowedRange() {
        OTPAuthURIBuilder.fromKey(totpKey).digits(TOTPBuilder.MAX_ALLOWED_DIGITS + 1);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void digitsForHOTPUriShouldFailWhenOutOfAllowedRange() {
        OTPAuthURIBuilder.fromKey(hotpKey).digits(HOTPBuilder.MAX_ALLOWED_DIGITS + 1);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void counterShouldFailWhenArgumentIsLessThanZero() {
        OTPAuthURIBuilder.fromKey(hotpKey).counter(-1);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void timeStepShouldFailWhenArgumentIsZero() {
        OTPAuthURIBuilder.fromKey(totpKey).timeStep(0);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void timeStepShouldFailWhenArgumentIsLessThanZero() {
        OTPAuthURIBuilder.fromKey(totpKey).timeStep(-1);
    }
    
    @Test(expected = IllegalStateException.class)
    public void buildShouldFailWhenLabelWasNeverSet() {
        OTPAuthURIBuilder.fromKey(totpKey).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build();
    }
    
    @Test(expected = IllegalStateException.class)
    public void buildShouldFailWhenIssuerAndLabelAccountNameAreDifferent() {
        OTPAuthURIBuilder.fromKey(totpKey).label(ISSUER + "1:foobar").issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build();
    }
    
    @Test
    public void buildTOTPUriShouldSucceed() {
        OTPAuthURI uri = OTPAuthURIBuilder.fromKey(totpKey).label(LABEL).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build();
        String expected = String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d", LABEL, totpKey.getKey(), ISSUER, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toPlainTextUriString());
        expected = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), 
                ISSUER_ENC, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        
        // No label issuer prefix.
        uri = OTPAuthURIBuilder.fromKey(totpKey).label(ACCOUNT_NM).issuer(ISSUER).digits(DIGITS).timeStep(TIMESTEP_MS).build();
        expected = String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d", ACCOUNT_NM_ENC, totpKey.getKey(), 
                ISSUER_ENC, DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
        
        // No issuer parameter.
        uri = OTPAuthURIBuilder.fromKey(totpKey).label(LABEL).issuer(null).digits(DIGITS).timeStep(TIMESTEP_MS).build();
        expected = String.format("otpauth://totp/%s:%s?secret=%s&digits=%d&period=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), 
                DIGITS, TIMESTEP_SEC);
        assertEquals(expected, uri.toUriString());
    }
    
    @Test
    public void buildHOTPUriShouldSucceed() {
        OTPAuthURI uri = OTPAuthURIBuilder.fromKey(hotpKey).label(LABEL).issuer(ISSUER).digits(DIGITS).counter(COUNTER).build();
        String expected = String.format("otpauth://hotp/%s?secret=%s&issuer=%s&digits=%d&counter=%d", LABEL, hotpKey.getKey(), ISSUER, DIGITS, COUNTER);
        assertEquals(expected, uri.toPlainTextUriString());
        expected = String.format("otpauth://hotp/%s:%s?secret=%s&issuer=%s&digits=%d&counter=%d", ISSUER_ENC, ACCOUNT_NM_ENC, hotpKey.getKey(), 
                ISSUER_ENC, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        
        // No label issuer prefix.
        uri = OTPAuthURIBuilder.fromKey(hotpKey).label(ACCOUNT_NM).issuer(ISSUER).digits(DIGITS).counter(COUNTER).build();
        expected = String.format("otpauth://hotp/%s?secret=%s&issuer=%s&digits=%d&counter=%d", ACCOUNT_NM_ENC, totpKey.getKey(), ISSUER_ENC, DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
        
        // No issuer parameter.
        uri = OTPAuthURIBuilder.fromKey(hotpKey).label(LABEL).issuer(null).digits(DIGITS).counter(COUNTER).build();
        expected = String.format("otpauth://hotp/%s:%s?secret=%s&digits=%d&counter=%d", ISSUER_ENC, ACCOUNT_NM_ENC, totpKey.getKey(), DIGITS, COUNTER);
        assertEquals(expected, uri.toUriString());
    }

    @Test(expected = NullPointerException.class)
    public void fromUriStringShouldFailWhenArgumentIsNull() {
        OTPAuthURIBuilder.fromUriString(null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenArgumentIsNotOfOTPAuthURIFormat() {
        OTPAuthURIBuilder.fromUriString("http://www.example.com/example?foo=bar");
    }
    
    @Test
    public void fromUriStringShouldFailWhenSecretParameterIsMissing() {
        try {
            OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?issuer=foo&digits=6&period=30");
            fail("The fromUriString call should have failed when the secret parameter is missing!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
        try {
            OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=&issuer=foo&digits=6&period=30");
            fail("The fromUriString call should have failed when the secret parameter value is missing!");
        } catch (IllegalArgumentException ignore) {
            // expected
        }
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenIssuerParameterValueIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=12345&issuer=&digits=6&period=30");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenDigitsParameterIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=12345&issuer=foo&period=30");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenDigitsParameterValueIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=123456&issuer=foo&digits=&period=30");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenDigitsParameterValueIsNotAnInteger() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=123456&issuer=foo&digits=6A&period=30");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenCounterParameterIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://hotp/foo:bar?secret=12345&issuer=foo&digits=6");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenCounterParameterValueIsPresentInNonHOTPUri() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=12345&issuer=foo&digits=6&counter=1");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenCounterParameterValueIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://hotp/foo:bar?secret=12345&issuer=foo&digits=6&counter=");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenCounterParameterValueIsNotALong() {
        OTPAuthURIBuilder.fromUriString("otpauth://hotp/foo:bar?secret=123456&issuer=foo&digits=6&counter=6A");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenPeriodParameterIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=12345&issuer=foo&digits=6");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenPeriodParameterValueIsPresentInNonTOTPUri() {
        OTPAuthURIBuilder.fromUriString("otpauth://hotp/foo:bar?secret=12345&issuer=foo&digits=6&period=30");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenPeriodParameterValueIsMissing() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=12345&issuer=foo&digits=6&period=");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void fromUriStringShouldFailWhenPeriodParameterValueIsNotALong() {
        OTPAuthURIBuilder.fromUriString("otpauth://totp/foo:bar?secret=123456&issuer=foo&digits=6&period=30A");
    }
    
    @Test
    public void fromUriStringShouldSucceedForTOTPBasedUri() {
        String sUri = "otpauth://totp/foo%20corporation:bar%20baz?secret=123456&issuer=foo%20corporation&digits=6&period=30";
        OTPAuthURI uri = OTPAuthURIBuilder.fromUriString(sUri).build();
        assertTrue(uri.isTOTP());
        assertFalse(uri.isHOTP());
        assertEquals("foo corporation:bar baz", uri.getLabel());
        assertEquals("foo%20corporation:bar%20baz", uri.getEncodedLabel());
        assertEquals("foo corporation", uri.getIssuer());
        assertEquals("foo%20corporation", uri.getEncodedIssuer());
        assertEquals(6, uri.getDigits());
        assertEquals(30, uri.getTimeStep());
        assertEquals(sUri, uri.toUriString());
        assertEquals("otpauth://totp/foo corporation:bar baz?secret=123456&issuer=foo corporation&digits=6&period=30", uri.toPlainTextUriString());
    }
    
    @Test
    public void fromUriStringShouldSucceedForHOTPBasedUri() {
        String sUri = "otpauth://hotp/foo%20corporation:bar%20baz?secret=123456&issuer=foo%20corporation&digits=6&counter=10";
        OTPAuthURI uri = OTPAuthURIBuilder.fromUriString(sUri).build();
        assertTrue(uri.isHOTP());
        assertFalse(uri.isTOTP());
        assertEquals("foo corporation:bar baz", uri.getLabel());
        assertEquals("foo%20corporation:bar%20baz", uri.getEncodedLabel());
        assertEquals("foo corporation", uri.getIssuer());
        assertEquals("foo%20corporation", uri.getEncodedIssuer());
        assertEquals(6, uri.getDigits());
        assertEquals(10, uri.getCounter());
        assertEquals(sUri, uri.toUriString());
        assertEquals("otpauth://hotp/foo corporation:bar baz?secret=123456&issuer=foo corporation&digits=6&counter=10", uri.toPlainTextUriString());
    }
    
    //TODO more test cases for fromUriString i.e. edge case(s)?
    
}
