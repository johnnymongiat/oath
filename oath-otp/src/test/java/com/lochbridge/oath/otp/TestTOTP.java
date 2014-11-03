package com.lochbridge.oath.otp;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class TestTOTP {

    private TOTP totp;

    @Before
    public void setUp() {
        totp = new TOTP("123456", System.currentTimeMillis(), HmacShaAlgorithm.HMAC_SHA_1, 6, 30000L);
    }

    @Test
    public void hashCodeShouldBeBasedOnTOTPValue() {
        assertEquals(totp.value().hashCode(), totp.hashCode());
    }

    @Test
    public void equalsShouldBeBasedOnTOTPValue() {
        assertEquals(totp, new TOTP(totp.value(), totp.time() + 1, HmacShaAlgorithm.HMAC_SHA_256, 8, 10000L));
        assertEquals(totp, totp);
        assertFalse(totp.equals(null));
        assertFalse(totp.equals(totp.value()));
    }

}
