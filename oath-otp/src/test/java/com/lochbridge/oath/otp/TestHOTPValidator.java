package com.lochbridge.oath.otp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.lochbridge.oath.otp.RFC4226TestVectors.TestVector;

public class TestHOTPValidator {

    @Test
    public void validateShouldSucceedUnderRFC4226TestCases() {
        for (TestVector testVector : RFC4226TestVectors.TEST_VECTORS) {
            HOTPValidationResult result = HOTPValidator.defaultLookAheadWindow().validate(testVector.getKey(), 
                    testVector.getMovingFactor(), testVector.getDigits(), testVector.getHotp());
            assertTrue(result.isValid());
            assertEquals(testVector.getMovingFactor() + 1, result.getNewMovingFactor());
        }
    }

    @Test
    public void validateShouldSucceedWithArbitraryLookAheadWindow() {
        long movingFactor = 5;
        HOTP source = HOTP.key(RFC4226TestVectors.KEY).movingFactor(movingFactor).build();
        HOTPValidationResult result = 
                HOTPValidator.lookAheadWindow((int) movingFactor).validate(RFC4226TestVectors.KEY, source.movingFactor(), source.digits(), source.value());
        assertTrue(result.isValid());
        assertEquals(source.movingFactor() + 1, result.getNewMovingFactor());
    }

    @Test
    public void validateShouldNotPassWithArbitraryLookAheadWindowAndUnsynchronizedMovingFactor() {
        HOTP source = HOTP.key(RFC4226TestVectors.KEY).movingFactor(5).build();
        long validationMovingFactor = source.movingFactor() - 2;
        HOTPValidationResult result = 
                HOTPValidator.lookAheadWindow(1).validate(RFC4226TestVectors.KEY, validationMovingFactor, source.digits(), source.value());
        assertFalse(result.isValid());
        assertEquals(validationMovingFactor, result.getNewMovingFactor());
    }

    @Test(expected = IllegalArgumentException.class)
    public void lookAheadWindowShouldFailWhenArgumentIsLessThanOne() {
        HOTPValidator.lookAheadWindow(0);
    }

}
