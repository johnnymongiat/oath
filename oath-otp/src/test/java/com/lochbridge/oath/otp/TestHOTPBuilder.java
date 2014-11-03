package com.lochbridge.oath.otp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.lochbridge.oath.otp.RFC4226TestVectors.TestVector;

public class TestHOTPBuilder {

    @Test
    public void buildShouldSucceedUnderRFC4226TestCases() {
        for (TestVector testVector : RFC4226TestVectors.TEST_VECTORS) {
            HOTP hotp = HOTP.key(testVector.getKey()).digits(testVector.getDigits()).movingFactor(testVector.getMovingFactor()).build();
            assertEquals(testVector.getHotp(), hotp.value());
        }
    }

    @Test
    public void buildShouldSucceedWhenBuilderIsReused() {
        TestVector testVector = RFC4226TestVectors.TEST_VECTORS.iterator().next();
        HOTPBuilder builder = HOTP.key(testVector.getKey()).digits(testVector.getDigits()).movingFactor(testVector.getMovingFactor());
        for (int i = 0; i < 5; i++) {
            HOTP hotp = builder.build();
            assertEquals(testVector.getHotp(), hotp.value());
            assertEquals(testVector.getDigits(), hotp.digits());
            assertEquals(testVector.getMovingFactor(), hotp.movingFactor());
        }
    }

    @Test
    public void generatedHOTPShouldBeConsistentWithConfiguredParameters() {
        final long expectedMovingFactor = 10;
        final int expectedDigits = 8;
        HOTP hotp = HOTP.key(RFC4226TestVectors.KEY).digits(expectedDigits).movingFactor(expectedMovingFactor).build();
        assertEquals(expectedMovingFactor, hotp.movingFactor());
        assertEquals(expectedDigits, hotp.digits());
    }

    @Test(expected = NullPointerException.class)
    public void constructorShouldFailWhenArgumentIsNull() {
        new HOTPBuilder(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void movingFactorShouldFailWhenArgumentIsLessThanZero() {
        new HOTPBuilder(RFC4226TestVectors.KEY).movingFactor(-1);
    }

    @Test
    public void digitsShouldFailWhenArgumentIsNotInValidRange() {
        HOTPBuilder builder = new HOTPBuilder(RFC4226TestVectors.KEY);
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

}
