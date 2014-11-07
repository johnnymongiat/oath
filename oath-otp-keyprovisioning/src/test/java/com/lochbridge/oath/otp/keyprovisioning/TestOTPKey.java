package com.lochbridge.oath.otp.keyprovisioning;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;

public class TestOTPKey {

    @Test(expected = NullPointerException.class)
    public void constructorShouldFailWhenKeyArgumentIsNull() {
        new OTPKey(null, OTPType.HOTP);
    }

    @Test(expected = NullPointerException.class)
    public void constructorShouldFailWhenTypeArgumentIsNull() {
        new OTPKey("123", null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void otpTypeEnumFromShouldFailWhenNoMatch() {
        OTPType.from("foobar");
    }

    @Test
    public void otpTypeEnumFromShouldSucceed() {
        assertEquals(OTPType.HOTP, OTPType.from(OTPType.HOTP.getName()));
    }

    @Test
    public void toStringShouldBeEquivalentToGetName() {
        assertEquals(OTPType.HOTP.getName(), OTPType.HOTP.toString());
    }

}
