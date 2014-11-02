package com.lochbridge.oath.otp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.lochbridge.oath.otp.RFC6238TestVectors.TestVector;

public class TestTOTPBuilder {
	
	@Test
    public void buildShouldSucceedUnderRFC6238TestCases() {
    	for (TestVector testVector : RFC6238TestVectors.TEST_VECTORS) {
    		TOTP totp = TOTP.key(testVector.getKey())
    				.timeStep(testVector.getTimeStep())
    				.digits(testVector.getDigits())
    				.hmacSha(testVector.getAlgorithm())
    				.build(testVector.getTestTime());
        	assertEquals(testVector.getTotp(), totp.value());
        }
    }
	
	@Test(expected=IllegalArgumentException.class)
    public void buildShouldFailWhenTimeArgumentIsLessThanZero() {
		new TOTPBuilder(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).build(-1L);
	}
	
	@Test
    public void generatedTOTPShouldBeConsistentWithConfiguredParameters() {
		final long expectedTimeStep = TimeUnit.SECONDS.toMillis(30);
		final int expectedDigits = 8;
		final long expectedTestTime = System.currentTimeMillis();
		
		TOTP totp = TOTP.key(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).timeStep(expectedTimeStep).digits(expectedDigits).hmacSha1().build(expectedTestTime);
		assertEquals(expectedTimeStep, totp.timeStep());
		assertEquals(expectedDigits, totp.digits());
		assertEquals(HmacShaAlgorithm.HMAC_SHA_1, totp.hmacShaAlgorithm());
		assertEquals(expectedTestTime, totp.time());
		
		totp = TOTP.key(RFC6238TestVectors.KEY_FOR_HMAC_SHA_256).timeStep(expectedTimeStep).digits(expectedDigits).hmacSha256().build(expectedTestTime);
		assertEquals(expectedTimeStep, totp.timeStep());
		assertEquals(expectedDigits, totp.digits());
		assertEquals(HmacShaAlgorithm.HMAC_SHA_256, totp.hmacShaAlgorithm());
		assertEquals(expectedTestTime, totp.time());
		
		totp = TOTP.key(RFC6238TestVectors.KEY_FOR_HMAC_SHA_512).timeStep(expectedTimeStep).digits(expectedDigits).hmacSha512().build(expectedTestTime);
		assertEquals(expectedTimeStep, totp.timeStep());
		assertEquals(expectedDigits, totp.digits());
		assertEquals(HmacShaAlgorithm.HMAC_SHA_512, totp.hmacShaAlgorithm());
		assertEquals(expectedTestTime, totp.time());
    }
	
	@Test(expected=NullPointerException.class)
    public void constructorShouldFailWhenArgumentIsNull() {
		new TOTPBuilder(null);
	}
	
	@Test(expected=IllegalArgumentException.class)
    public void timeStepShouldFailWhenArgumentIsZero() {
		new TOTPBuilder(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).timeStep(0);
	}
	
	@Test(expected=IllegalArgumentException.class)
    public void timeStepShouldFailWhenArgumentIsLessThanZero() {
		new TOTPBuilder(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).timeStep(-1);
	}
	
	@Test
    public void digitsShouldFailWhenArgumentIsNotInValidRange() {
		TOTPBuilder builder = new TOTPBuilder(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1);
		try {
			builder.digits(5);
			fail("Should have failed since digits argument is in invalid range!");
		} catch (IllegalArgumentException ignore) {
			// expected
		}
		try {
			builder.digits(9);
			fail("Should have failed since digits argument is outside the valid range!");
		} catch (IllegalArgumentException ignore) {
			// expected
		}
	}
	
	@Test(expected=NullPointerException.class)
    public void hmacShaShouldFailWhenArgumentIsNull() {
		new TOTPBuilder(RFC6238TestVectors.KEY_FOR_HMAC_SHA_1).hmacSha(null);
	}

}
