package com.lochbridge.oath.otp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.lochbridge.oath.otp.RFC6238TestVectors.TestVector;

public class TestTOTPValidator {
	
	@Test
    public void isValidShouldSucceedUnderRFC6238TestCases() {
        for (TestVector testVector : RFC6238TestVectors.TEST_VECTORS) {
        	assertTrue(TOTPValidator.window(0).isValid(
        			testVector.getKey(), 
        			testVector.getTimeStep(), 
        			testVector.getDigits(), 
        			testVector.getAlgorithm(), 
        			testVector.getTotp(), 
        			testVector.getTestTime()));
        }
    }
	
	@Test
    public void isValidShouldSucceedWithDefaultWindow() {
		TOTP source = TOTP.key(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).hmacSha1().build();
		assertTrue(TOTPValidator.defaultWindow().isValid(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1, source.timeStep(), source.digits(), source.hmacShaAlgorithm(), source.value()));
		
		long time = System.currentTimeMillis();
		source = TOTP.key(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).hmacSha1().build(time);
		assertTrue(TOTPValidator.defaultWindow().isValid(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1, source.timeStep(), source.digits(), source.hmacShaAlgorithm(), source.value(), time));
    }
	
	@Test
    public void isValidShouldReturnFalseWithDelayedValidation() {
		final long time = System.currentTimeMillis();
		final long validationTime = time + TimeUnit.HOURS.toMillis(1);
		TOTP source = TOTP.key(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).hmacSha1().build(time);
		assertFalse(TOTPValidator.defaultWindow().isValid(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1, source.timeStep(), source.digits(), source.hmacShaAlgorithm(), source.value(), validationTime));
    }
	
	@Test(expected=IllegalArgumentException.class)
    public void windowShouldFailWhenArgumentIsLessThanZero() {
		TOTPValidator.window(-1);
	}

}
